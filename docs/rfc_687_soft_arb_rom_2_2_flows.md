# Caliptra 2.2 Soft Anti-Rollback (Soft ARB) ROM & Firmware Flow (RFC #687)

**Reference**: [`chipsalliance/Caliptra#687`](https://github.com/chipsalliance/Caliptra/issues/687) — *Caliptra Hitless Update: Anti-Rollback Policy and SVN Attestation*

---

## 1. Overview & SVN Taxonomy

Caliptra 2.2 introduces a volatile, monotonically non-decreasing anti-rollback floor (`fw_soft_svn`) that allows a privileged (`PL0`) caller to raise the minimum allowable firmware SVN within the current power cycle without burning fuses, while preserving existing cold-boot fuse enforcement (`fw_fuse_svn`) and key-ladder derivation (`fw_min_svn`).

| Field | Storage Location | Initialized On Cold Boot | Updated On Update Reset (`FIRMWARE_LOAD`) | Updated On Update Reset (`INCREASE_FW_SOFT_SVN`) | Preserved Across Warm Reset | Purpose & Consumers |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`fw_fuse_svn`** | Fuse Controller (`fuse_runtime_svn`, decoded to `0..=128`) | Read from fuse registers (`0` if `Unprovisioned` or `anti_rollback_disable`) | Unchanged (read from fuse registers) | Unchanged | Yes | Permanent hardware anti-rollback floor; reported in FMC Alias and RT Alias certificates |
| **`cold_boot_fw_svn`** | `DataVault::ColdResetEntries` (PMP `pmp1cfg`, Read-Only + Locked) | `manifest.header.svn` | Unchanged | Unchanged | Yes | Cold-boot firmware SVN; reported in FMC Alias certificate |
| **`fw_svn`** | `DataVault::WarmResetEntries` (PMP `pmp3cfg`, Read-Only + Locked) | `manifest.header.svn` | `new_manifest.header.svn` | Unchanged | Yes | Active running firmware SVN; reported in RT Alias certificate, DPE, and `FW_INFO` |
| **`fw_min_svn`** | `DataVault::WarmResetEntries` (PMP `pmp3cfg`, Read-Only + Locked) | `manifest.header.svn` | `min(old_fw_min_svn, new_manifest.header.svn)` | Unchanged | Yes | Lowest firmware SVN executed since cold boot; drives the Key Ladder (`KEY_ID_FE` / `KEY_ID_STABLE_*`) and is reported in RT Alias certificate |
| **`fw_soft_svn`** *(New)* | `DataVault::WarmResetEntries` (PMP `pmp3cfg`, Read-Only + Locked) | `effective_fuse_svn` | Unchanged (or raised if a valid soft-SVN advance is bundled) | `requested_soft_svn` (where `fw_soft_svn <= requested <= fw_svn`) | Yes | Volatile anti-rollback floor for the current power cycle; enforced by ROM on `FIRMWARE_LOAD` and reported in RT Alias certificate |

### Effective Anti-Rollback Floor

Whenever SVN enforcement is active (`lifecycle != Lifecycle::Unprovisioned && !soc_ifc.anti_rollback_disable()`), ROM enforces:

```text
effective_svn_floor = max(fw_fuse_svn, fw_soft_svn)
manifest.header.svn >= effective_svn_floor  &&  manifest.header.svn <= MAX_FIRMWARE_SVN (128)
```

---

## 2. Storage & Hardware Access Control (`DataVault` + RISC-V PMP)

### 2.1 Why `DataVault::WarmResetEntries` Instead of Key Vault

1. **CPU Readability**: Hardware Key Vault slots (`KV0`–`KV23`) are accessible only to cryptographic and DMA engines via `kv_rd_ctrl`; the RISC-V CPU cannot read a numeric SVN value back from a Key Vault slot to compare `manifest.header.svn >= fw_soft_svn` in ROM or serialize `fw_soft_svn` into the RT Alias X.509 certificate in FMC.
2. **Slot Availability**: All 24 Key Vault slots (`KV0`–`KV23`) are allocated across DICE identities, PCR signing keys, key ladder slots, ephemeral scratch slots, and OCP-LOCK slots.
3. **Hardware-Enforced ROM-Only Write / FMC+RT Read via PMP**:
   * `DataVault` resides in DCCM inside `RomPersistentData` (`drivers/src/persistent.rs:480`), which has a fixed `15 KiB` reservation (`DATAVAULT_MAX_SIZE`).
   * Before jumping to FMC on every boot path (`rom/dev/src/main.rs:241`, `rom/dev/src/lock.rs:25-76`), ROM programs RISC-V Physical Memory Protection (PMP) entries with **`Permission::R` and `locked = true` (`L=1`)**:
     * `pmp1cfg` / `pmp0addr`–`pmp1addr`: locks `DataVault::ColdResetEntries` Read-Only.
     * `pmp3cfg` / `pmp2addr`–`pmp3addr`: locks `DataVault::WarmResetEntries` Read-Only.
   * In RISC-V privileged architecture, setting `L=1` on a PMP entry enforces Read-Only permissions even in Machine Mode (M-mode, where FMC and Runtime execute) and **prevents FMC or Runtime from modifying the PMP CSRs**.
   * The PMP `L` bit can only be cleared by a CPU reset (Cold Reset, Warm Reset, or Update Reset), which resets `pc` to the ROM entry vector (`0x0000_0000`).
   * Consequently, **only ROM can write `WarmResetEntries` (during Cold Reset and Update Reset prior to `lock_registers`), while FMC and Runtime have direct Read-Only access**. Any store instruction targeting `WarmResetEntries` from FMC or Runtime raises a hardware Store Access Fault (`mcause = 0x7`).

### 2.2 Memory Footprint Impact

Adding `fw_soft_svn: u32` to `WarmResetEntries` (`drivers/src/data_vault.rs:39`) increases `size_of::<WarmResetEntries>()` by `4` bytes, which is absorbed by the existing `reserved1_1` padding inside `RomPersistentData` (`drivers/src/persistent.rs:481`). Total DCCM `.bss`/`.data` growth is **0 bytes**.

---

## 3. Cold Reset Flow (Current vs. New)

### 3.1 End-to-End Cold Reset Sequence

1. **ROM Entry & Hardware Initialization (`rom/dev/src/main.rs:rom_entry`)**:
   * Initializes TRNG, runs CSRNG KAT, initializes CFI counters, constructs `RomEnv` (`reset_reason == ResetReason::ColdReset`), seeds ABR entropy, validates TRNG config, runs UDS programming if requested, sets `rom_fw_rev_id`, starts WDT, runs FIPS KATs + ROM integrity check, and runs debug unlock if requested.
2. **Cold Reset Setup & Device Identity Derivation (`rom/dev/src/flow/cold_reset/mod.rs:ColdResetFlow::run`)**:
   * Initializes `RomPersistentData` header (`marker`, `major_version`, `minor_version`, `boot_mode = BootMode::Normal`).
   * Sets `data_vault.set_rom_cold_boot_status(ColdResetStarted.into())`.
   * Initializes FHT (`fht::initialize_fht`), derives `InitDevIdLayer` and `LocalDevIdLayer`, and generates CMB AES key shares.
3. **Firmware Download & Verification (`rom/dev/src/flow/cold_reset/fw_processor/mod.rs:FirmwareProcessor::process`)**:
   * Downloads the firmware image manifest (`FIRMWARE_LOAD` via mailbox or subsystem recovery DMA).
   * Invokes `FirmwareProcessor::verify_image` → `ImageVerifier::verify` (`image/verify/src/verifier.rs:69`):
     * Verifies `ImagePreamble` vendor/owner public keys against fuses and verifies header signatures (`verify_preamble`, `verify_header`).
     * Verifies `toc_digest` (`verify_toc`) and FMC/Runtime image digests (`verify_fmc`, `verify_runtime`).
     * Calls `verify_svn(manifest.header.svn)` and computes `effective_fuse_svn = self.effective_fuse_svn()`.
4. **DataVault & Key Ladder Initialization (`rom/dev/src/flow/cold_reset/fw_processor/mod.rs:1007-1050`)**:
   * **Current**: `populate_data_vault()` writes `fmc_tci`, `cold_boot_fw_svn = info.fw_svn`, `fmc_entry_point`, `owner_pk_hash`, `vendor_ecc_pk_index`, `vendor_pqc_pk_index` into `ColdResetEntries`, and writes `rt_tci`, `fw_svn = info.fw_svn`, `fw_min_svn = info.fw_svn`, `rt_entry_point`, `manifest_addr` into `WarmResetEntries`.
   * **New**: `populate_data_vault()` additionally initializes:
     ```rust
     data_vault.set_fw_soft_svn(info.effective_fuse_svn);
     ```
     *Note*: At `populate_data_vault()` time on Cold Reset, `fw_soft_svn` is set to `info.effective_fuse_svn` (`fw_fuse_svn` when anti-rollback is enabled, or `0` when unprovisioned / anti-rollback is disabled). During `verify_svn()` on Cold Reset, `fw_soft_svn` in `WarmResetEntries` is still `0` (zero-initialized DCCM), so `max(fw_fuse_svn, fw_soft_svn) == fw_fuse_svn`.
   * `populate_fw_key_ladder()` initializes the key ladder in `KEY_ID_FE` / `KEY_ID_STABLE_*` with `chain_len = MAX_FIRMWARE_SVN - info.fw_svn`.
   * Extends `PCR0` (`PCR_ID_FMC_CURRENT`) and `PCR1` (`PCR_ID_FMC_JOURNEY`), loads FMC and Runtime into ICCM, completes the `FIRMWARE_LOAD` mailbox transaction, and stores `manifest1` in `RomPersistentData`.
5. **FMC Alias Derivation & ROM Exit (`rom/dev/src/flow/cold_reset/fmc_alias.rs`)**:
   * Derives `KEY_ID_ROM_FMC_CDI` (`KV6`), FMC Alias keys, and PCR signing keys; generates the FMC Alias X.509 TBS certificates (`EccFmcalias`, `MldsaFmcalias`) using `cold_boot_fw_svn` and `fw_fuse_svn` (static for the entire cold-boot cycle).
   * Sets `data_vault.set_rom_cold_boot_status(ColdResetComplete.into())`.
   * `lock_registers(env, ResetReason::ColdReset)` locks both `ColdResetEntries` (`pmp1cfg`) and `WarmResetEntries` (`pmp3cfg`) Read-Only via PMP, locks `PCR0`/`PCR1`/`PCR31`, locks ICCM, and launches FMC (`launch_fmc`).
6. **FMC & Runtime Cold Boot Execution (`fmc/src/flow/rt_alias.rs`, `runtime/src/drivers.rs`)**:
   * FMC extends `PCR2` (`RT_FW_CURRENT_PCR`) and `PCR3` (`RT_FW_JOURNEY_PCR`), derives `KEY_ID_RT_CDI` (`KV4`) and RT Alias keys (`KV9`/`KV10`), and generates the RT Alias X.509 TBS certificates (`RtAliasCertTbsEcc384`, `RtAliasCertTbsMlDsa87`).
   * **New in FMC (`fmc/src/flow/rt_alias.rs`)**: Populates the RT Alias certificate TCB Info extension with the dynamic SVN fields read from `DataVault`: `fw_svn` (`HandOff::fw_svn`), `fw_min_svn` (`HandOff::fw_min_svn`), `fw_fuse_svn`, and `fw_soft_svn` (`HandOff::fw_soft_svn`).
   * Runtime initializes DPE (`Drivers::initialize_dpe`) and begins servicing mailbox commands.

### 3.2 Cold Reset Comparison Summary

| Step | Component / Function | Current Behavior | New Behavior (RFC #687) |
| :--- | :--- | :--- | :--- |
| **1. SVN Verification** | `ImageVerifier::verify_svn` (`image/verify/src/verifier.rs:144`) | Checks `fw_svn <= 128` and (if `svn_check_required`) `fw_svn >= env.fw_fuse_svn()` | Checks `fw_svn <= 128` and (if `svn_check_required`) `fw_svn >= max(env.fw_fuse_svn(), env.fw_soft_svn())` (equals `fw_fuse_svn` on Cold Boot since `fw_soft_svn` starts at `0`) |
| **2. DataVault Init** | `FirmwareProcessor::populate_data_vault` (`fw_processor/mod.rs:1007`) | Sets `cold_boot_fw_svn = info.fw_svn`, `fw_svn = info.fw_svn`, `fw_min_svn = info.fw_svn` | Also sets `data_vault.set_fw_soft_svn(info.effective_fuse_svn)` |
| **3. Key Ladder Init** | `FirmwareProcessor::populate_fw_key_ladder` (`fw_processor/mod.rs:1029`) | Initializes key ladder to `MAX_FIRMWARE_SVN - fw_svn` | Unchanged (key ladder remains tied to `fw_min_svn`, not `fw_soft_svn`) |
| **4. FMC Alias Cert** | `FmcAliasLayer::derive` (`fmc_alias.rs`) | Attests `cold_boot_fw_svn` and `fw_fuse_svn` | Unchanged (FMC Alias certificate remains static for the boot cycle) |
| **5. PMP Locking** | `lock_registers` (`rom/dev/src/lock.rs:32`) | Locks `ColdResetEntries` (`pmp1cfg`) and `WarmResetEntries` (`pmp3cfg`) Read-Only | Unchanged (`fw_soft_svn` in `WarmResetEntries` is automatically covered by `pmp3cfg`) |
| **6. RT Alias Cert** | `RtAliasLayer::run` (`fmc/src/flow/rt_alias.rs:119`) | Encodes `tcb_info_fw_svn = HandOff::fw_svn(env)` | Encodes active/min/fuse/soft SVN policy fields (`fw_svn`, `fw_min_svn`, `fw_fuse_svn`, `fw_soft_svn`) in RT Alias TCB Info |

---

## 4. Update Reset Flow (Current vs. New)

Currently, `UpdateResetFlow::run` (`rom/dev/src/flow/update_reset.rs:37`) supports only `CommandId::FIRMWARE_LOAD`. Under RFC #687, `UpdateResetFlow::run` dispatches between two subflows based on the active mailbox command (`actual_cmd`):

1. **`CommandId::FIRMWARE_LOAD`**: Hitless Runtime firmware update, enforcing the active `fw_soft_svn` floor.
2. **`CommandId::INCREASE_FW_SOFT_SVN`**: Privileged (`PL0`) soft anti-rollback floor ratchet without loading a new firmware image.

```text
Runtime (PL0 Mailbox Command)
  ├── CommandId::FIRMWARE_LOAD         ──► Leave mbox txn open ──► assert_fw_update_reset()
  └── CommandId::INCREASE_FW_SOFT_SVN  ──► Leave mbox txn open ──► assert_fw_update_reset()
                                                                         │
                                                                         ▼
ROM Entry (ResetReason::UpdateReset)
  ├── lock_cold_reset_reg() (re-applies pmp1cfg Read-Only lock on ColdResetEntries)
  ├── run_fips_tests() (with ShaAccLockState::NotAcquired)
  └── UpdateResetFlow::run()
        ├── Re-apply Key Vault write/use locks (OCP-LOCK, STABLE_*, PCR_*)
        ├── Verify RomPersistentData MAGIC and MAJOR_VERSION
        ├── Read open mailbox txn (supporting direct mbox or EXTERNAL_MAILBOX_CMD)
        ├── Match actual_cmd:
        │     ├── CommandId::FIRMWARE_LOAD        ──► Subflow A (Section 4.1)
        │     └── CommandId::INCREASE_FW_SOFT_SVN ──► Subflow B (Section 4.2)
        └── On error before ICCM overwrite:
              ├── report_fw_error_non_fatal(err)
              └── Restore UpdateResetComplete if previous state was valid
  │
  ▼
lock_registers(ResetReason::UpdateReset) (applies pmp3cfg Read-Only lock on WarmResetEntries)
  │
  ▼
launch_fmc() ──► FMC RtAliasLayer::run() (re-signs RT Alias cert) ──► Runtime::run_reset_flow()
```

### 4.1 Subflow A: `CommandId::FIRMWARE_LOAD` (Hitless Firmware Update)

#### Current Flow (`rom/dev/src/flow/update_reset.rs`)
1. Runtime receives `CommandId::FIRMWARE_LOAD` (`runtime/src/lib.rs`, `runtime/src/update.rs`), verifies `PL0` privilege and request checksum, leaves the mailbox transaction open, and asserts `soc_ifc.assert_fw_update_reset()`.
2. ROM enters `UpdateResetFlow::run()`, sets `rom_update_reset_status = UpdateResetStarted`, acquires the open mailbox transaction (`env.mbox.try_start_recv_txn()`), and extracts `(actual_cmd, staging_addr, img_bundle_sz)`.
3. Loads `ImageManifest` from mailbox SRAM or MCU SRAM / AXI staging memory (`Self::load_manifest`).
4. Runs `Self::verify_image` → `ImageVerifier::verify`:
   * Verifies preamble keys, header signatures, TOC digest, FMC digest (must match `data_vault.fmc_tci()`), and Runtime digest.
   * Calls `verify_svn(manifest.header.svn)`, which currently checks `manifest.header.svn >= env.fw_fuse_svn()` (when `svn_check_required()`).
5. Calls `Self::populate_data_vault(data_vault, info, &mut env.hmac, &mut env.trng)`:
   * Updates `rt_tci`, `fw_svn = info.fw_svn`, `fw_min_svn = min(old_min_svn, info.fw_svn)`, `rt_entry_point`.
   * Extends the key ladder by `decrement_by = old_min_svn - new_min_svn` (`key_ladder::extend_key_ladder`).
6. Extends `PCR0` and `PCR1` (`pcr::extend_pcrs`), loads the new Runtime binary into ICCM (`Self::load_image`), re-verifies ICCM Runtime digest (`loaded_image::verify_runtime`), completes the mailbox transaction (`recv_txn.complete(true)`), updates `persistent_data.rom.manifest1 = manifest`, updates `rt_fw_rev_id`, and sets `rom_update_reset_status = UpdateResetComplete`.

#### New Changes in Subflow A (`CommandId::FIRMWARE_LOAD`)
1. **`FirmwareVerificationEnv::fw_soft_svn(&mut self) -> u32` (`common/src/verifier.rs`, `rom/dev/src/flow/update_reset.rs`)**:
   * Exposes `self.data_vault.fw_soft_svn()` through the `ImageVerificationEnv` trait.
2. **Soft ARB Floor Enforcement in `ImageVerifier::verify_svn` (`image/verify/src/verifier.rs:144-160`)**:
   * When `self.svn_check_required()` is true:
     ```rust
     let effective_floor = core::cmp::max(self.env.fw_fuse_svn(), self.env.fw_soft_svn());
     if cfi_launder(fw_svn) < effective_floor {
         Err(CaliptraError::IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE)?; // or dedicated SOFT_SVN error when fw_svn >= fw_fuse_svn
     } else {
         cfi_assert_ge(fw_svn, effective_floor);
     }
     ```
   * If `manifest.header.svn < data_vault.fw_soft_svn()`, image verification fails *before* `populate_data_vault`, key-ladder extension, PCR extension, or ICCM overwrite.
3. **Non-Fatal Rollback Failure Recovery**:
   * When `verify_image` fails due to `manifest.header.svn < fw_soft_svn`, `process_txn()` returns `Err(e)`, `report_fw_error_non_fatal(e.into())` records the error, `recv_txn` is dropped (marking the mailbox command as failed), and `rom_entry` continues to `lock_registers` and `launch_fmc`.
   * **Important Status Restoration**: Because the previous cold-boot/runtime image in ICCM is still intact and valid, `UpdateResetFlow` must either defer setting `rom_update_reset_status = UpdateResetStarted` until right before mutating persistent state (`populate_data_vault` / `load_image`) or restore `UpdateResetComplete` on pre-mutation verification failures so a subsequent Warm Reset does not fail with `ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET`.

---

### 4.2 Subflow B: `CommandId::INCREASE_FW_SOFT_SVN` (New Soft-SVN-Only Update Reset)

#### Mailbox Command Definition (`api/src/mailbox.rs`)
* **Command ID**: `CommandId::INCREASE_FW_SOFT_SVN` (new mailbox command ID).
* **Request Struct**:
  ```rust
  #[repr(C)]
  #[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Default, PartialEq, Eq, Debug)]
  pub struct IncreaseFwSoftSvnReq {
      pub hdr: MailboxReqHeader,
      pub soft_svn: u32,
  }
  ```
* **Privilege Level**: Restricted to `PL0` (`drivers.ensure_pl0()?` in Runtime).

#### Step-by-Step Sequence for `INCREASE_FW_SOFT_SVN`

1. **Step 1 — Runtime Command Reception (`runtime/src/lib.rs`, `runtime/src/update.rs`)**:
   * Runtime verifies `drivers.ensure_pl0()?` (rejecting non-`PL0` callers with `RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL`).
   * Runtime parses `IncreaseFwSoftSvnReq` from the mailbox buffer and verifies the request checksum.
   * Runtime performs an advisory fast-fail check:
     * `req.soft_svn <= MAX_FIRMWARE_SVN` (`128`)
     * `req.soft_svn >= drivers.persistent_data.get().rom.data_vault.fw_soft_svn()`
     * `req.soft_svn <= drivers.persistent_data.get().rom.data_vault.fw_svn()`
     *(If invalid, Runtime immediately returns an error without triggering an update reset. Note that ROM independently enforces all checks even if a compromised Runtime bypasses them.)*
   * Runtime leaves the mailbox transaction open in Mailbox SRAM (do **not** call `complete`) and calls `update::handle_impactless_update(drivers)` → `soc_ifc.assert_fw_update_reset()`.

2. **Step 2 — ROM Entry & Environment Setup (`rom/dev/src/main.rs`)**:
   * CPU resets to `rom_entry` with `reset_reason == ResetReason::UpdateReset`.
   * ROM immediately calls `lock_cold_reset_reg(&mut env)` to re-apply the PMP Read-Only lock (`pmp1cfg`) on `DataVault::ColdResetEntries`.
   * ROM runs KATs and dispatches `flow::run(&mut env)` → `UpdateResetFlow::run(&mut env)`.

3. **Step 3 — ROM Mailbox Dispatch & Authoritative Validation (`rom/dev/src/flow/update_reset.rs`)**:
   * ROM re-applies Key Vault write/use locks (`ocp_lock::wr_lock_keyvault`, `KEY_ID_STABLE_*`, `KEY_ID_PCR_*`) and validates `RomPersistentData::MAGIC` and `MAJOR_VERSION`.
   * ROM starts receiving the open mailbox transaction (`env.mbox.try_start_recv_txn()`).
   * When `actual_cmd == CommandId::INCREASE_FW_SOFT_SVN.into()`:
     * **Subsystem Mode Check**: If wrapped in `CommandId::EXTERNAL_MAILBOX_CMD`, or sent as a direct mailbox command, ROM reads `IncreaseFwSoftSvnReq` from the mailbox payload and verifies `caliptra_common::checksum::verify_checksum(req.hdr.chksum, CommandId::INCREASE_FW_SOFT_SVN.into(), &req.as_bytes()[size_of::<u32>()..])`.
     * **ROM Authoritative Policy Checks** (with `cfi_launder` / `cfi_assert_*`):
       1. `requested <= MAX_FIRMWARE_SVN` (`128`)
       2. `requested >= data_vault.fw_soft_svn()` (monotonic non-decreasing within the power cycle)
       3. `requested <= data_vault.fw_svn()` (cannot set the floor higher than the currently running authenticated firmware's SVN)
       4. `requested >= effective_fuse_svn` (guaranteed if `fw_soft_svn` was initialized to `effective_fuse_svn` on Cold Boot, checked explicitly for defense-in-depth)

4. **Step 4 — ROM Commit (No Firmware Reload)**:
   * If all checks pass:
     * ROM updates `DataVault::WarmResetEntries`:
       ```rust
       data_vault.set_fw_soft_svn(requested);
       ```
     * ROM completes the mailbox transaction (`recv_txn.complete(true)?`) and drops `recv_txn`.
     * ROM sets `data_vault.set_rom_update_reset_status(UpdateResetComplete.into())` and reports `UpdateResetComplete`.
     * **What ROM Does NOT Touch**:
       * Does **not** DMA or load a manifest or Runtime binary into ICCM.
       * Does **not** modify `manifest1`, `fw_svn`, `fw_min_svn`, `rt_tci`, or `rt_entry_point`.
       * Does **not** extend the Key Ladder (`KEY_ID_FE` / `KEY_ID_STABLE_*`).
       * Does **not** extend `PCR0` or `PCR1`.
   * If any check fails:
     * ROM leaves `data_vault.fw_soft_svn()` **unchanged**.
     * ROM calls `report_fw_error_non_fatal(err.into())`, leaves `rom_update_reset_status` as `UpdateResetComplete` (since the running firmware image was never modified), and returns `Err(err)` (dropping `recv_txn`, which fails the mailbox transaction).
     * `rom_entry` logs the non-fatal error, locks PMP registers, and jumps back to the existing FMC and Runtime.

5. **Step 5 — PMP Lock & Handoff to FMC (`rom/dev/src/main.rs:241`)**:
   * `lock_registers(&mut env, ResetReason::UpdateReset)` calls `lock_common_reg_set(&mut env)`, which locks `DataVault::WarmResetEntries` (including the newly committed `fw_soft_svn`) as **Read-Only + Locked (`Permission::R, locked = true`)** in `pmp3cfg`, locks `PCR0`/`PCR1`/`PCR31`, locks ICCM, and calls `launch_fmc(&mut env)`.

6. **Step 6 — FMC Execution on `INCREASE_FW_SOFT_SVN` (`fmc/src/flow/rt_alias.rs`)**:
   * FMC runs `RtAliasLayer::run(env)`:
     * Regenerates FMC Alias keys (`KV13`/`KV14`) from `KV6` (`KEY_ID_ROM_FMC_CDI`) and verifies they match the ROM-certified public keys in FHT.
     * Calls `Self::extend_pcrs(env)` (`fmc/src/flow/rt_alias.rs:236-247`):
       * Because `reset_reason == ResetReason::UpdateReset` and neither `rt_tci` nor `fw_svn` changed, `predicted_pcr == prev_pcr` is **true**.
       * Therefore, FMC **skips** `extend_pcr_common(env)` — `RT_FW_CURRENT_PCR` (`PCR2`) and `RT_FW_JOURNEY_PCR` (`PCR3`) are **not** re-extended!
     * Calls `Self::derive_cdi(env, KEY_ID_ROM_FMC_CDI, KEY_ID_RT_CDI)`:
       * Because `KEY_ID_ROM_FMC_CDI` (`KV6`) and `RT_FW_CURRENT_PCR` (`PCR2`, which holds `rt_tci`) are unchanged, `KEY_ID_RT_CDI` (`KV4`) and the derived RT Alias subject keys (`KV9`/`KV10`) remain **identical**.
     * Calls `Self::generate_cert_sig(env, ...)`:
       * Builds new `RtAliasCertTbsEcc384` and `RtAliasCertTbsMlDsa87` in DCCM with the updated `fw_soft_svn` from `DataVault`, signs them with the FMC Alias keys, use-locks `KV6`, and erases `KV13`/`KV14`.
   * FMC locks `PCR2`/`PCR3` and launches Runtime.

7. **Step 7 — Runtime Re-Entry on `INCREASE_FW_SOFT_SVN` (`runtime/src/drivers.rs:321-329`)**:
   * Runtime runs `Drivers::run_reset_flow()`:
     * Calls `Self::create_cert_chain(self)`, copying the newly signed RT Alias certificate (now containing the updated `fw_soft_svn`) into the Runtime certificate chain buffer.
     * Runs the `ResetReason::UpdateReset` arm (`validate_dpe_structure`, `validate_context_tags`, `init_dpe_index_cache`, `update_dpe_rt_tci`, `update_dpe_cciv`), which is idempotent when `rt_tci` and `PCR3` are unchanged.
     * Runtime enters its normal mailbox loop with the new `fw_soft_svn` active and attested in the RT Alias certificate.

---

## 5. Warm Reset Flow (Current vs. New)

### 5.1 End-to-End Warm Reset Sequence

1. **ROM Entry (`rom/dev/src/main.rs:rom_entry`)**:
   * CPU resets to `rom_entry` with `reset_reason == ResetReason::WarmReset` (DCCM contents, Key Vault contents, and PCR contents are preserved across Warm Reset by hardware; PMP CSRs and Key Vault lock bits are cleared by hardware reset).
   * ROM immediately calls `lock_cold_reset_reg(&mut env)` (`rom/dev/src/main.rs:116`) to re-apply the PMP Read-Only lock (`pmp1cfg`) on `DataVault::ColdResetEntries`.
   * ROM runs KATs and dispatches `flow::run(&mut env)` → `WarmResetFlow::run(&mut env)`.
2. **Warm Reset Validation (`rom/dev/src/flow/warm_reset.rs:WarmResetFlow::run`)**:
   * Re-applies Key Vault write/use locks (`ocp_lock::wr_lock_keyvault`, `KEY_ID_STABLE_*`, `KEY_ID_PCR_*`, plus `KEY_ID_ROM_FMC_CDI`).
   * Validates `RomPersistentData::MAGIC` and `MAJOR_VERSION`.
   * Verifies `data_vault.rom_cold_boot_status() == ColdResetComplete.into()`.
   * Verifies `data_vault.rom_update_reset_status() != UpdateResetStarted.into()`.
3. **PMP Lock & Handoff (`rom/dev/src/main.rs:241`)**:
   * `lock_registers(&mut env, ResetReason::WarmReset)` calls `lock_common_reg_set(&mut env)`, which re-applies the PMP Read-Only lock (`pmp3cfg`) on `DataVault::WarmResetEntries` (preserving `fw_soft_svn`, `fw_svn`, `fw_min_svn`, `rt_tci`, `rt_entry_point`).
   * Locks `PCR0`/`PCR1`/`PCR31`, locks ICCM, and launches FMC (`launch_fmc`).
4. **FMC & Runtime Execution (`fmc/src/flow/rt_alias.rs`, `runtime/src/drivers.rs`)**:
   * FMC regenerates FMC Alias keys from `KV6`, skips `PCR2`/`PCR3` extension (`ResetReason::WarmReset`), regenerates `RT_CDI` (`KV4`) and RT Alias keys (`KV9`/`KV10`), and re-generates the RT Alias X.509 TBS certificates using the preserved `fw_soft_svn`, `fw_min_svn`, `fw_fuse_svn`, and `fw_svn` from `DataVault`.
   * Runtime validates DPE structure/tags, checks `check_dpe_rt_pcrs_unchanged`, updates FW version registers, and enters its mailbox loop.

### 5.2 Warm Reset Comparison Summary

| Step | Component / Function | Current Behavior | New Behavior (RFC #687) |
| :--- | :--- | :--- | :--- |
| **1. `WarmResetFlow::run`** | `rom/dev/src/flow/warm_reset.rs:34` | Re-locks KV slots; checks `RomPersistentData` and `ColdResetComplete` / `UpdateResetStarted` | No logic change required; `fw_soft_svn` in `DataVault::WarmResetEntries` automatically persists in DCCM across Warm Reset |
| **2. PMP Locking** | `lock_registers` (`rom/dev/src/lock.rs:32`) | Locks `WarmResetEntries` (`pmp3cfg`) Read-Only | Automatically re-locks `fw_soft_svn` Read-Only before jumping to FMC |
| **3. FMC RT Alias Cert** | `RtAliasLayer::run` (`fmc/src/flow/rt_alias.rs:119`) | Re-generates RT Alias cert with `fw_svn` | Re-generates RT Alias cert with preserved `fw_soft_svn`, `fw_min_svn`, `fw_fuse_svn`, and `fw_svn` |

---

## 6. End-to-End Use-Case Combinations & Reported SVN Values

### 6.1 Step-by-Step Boot & Update Sequence (`fw_fuse_svn = 2`)

The table below traces a complete sequence of operations within a single power cycle (Steps 1–9) followed by the next Cold Boot (Step 10), starting with a fused floor of `fw_fuse_svn = 2`.

| # | Use Case / Action | Validation Rule & Outcome | FMC Alias Cert<br>(`cold_svn`, `fuse_svn`) | RT Alias Cert<br>(`fw_svn`, `min_svn`, `fuse_svn`, `soft_svn`) | Key Ladder<br>(`min_svn`) | `PCR2` / `PCR3`<br>(RT Current / Journey) |
| :- | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | **Cold Boot** with FW `SVN = 5` | `5 >= max(2, 2)` → **Accepted** | `(5, 2)` | `(5, 5, 2, 2)` | Initialized to `5` | Extended with `SVN 5` |
| **2** | **Hitless Downgrade** (`FIRMWARE_LOAD` `SVN = 3`) | `3 >= max(2, 2)` → **Accepted** | `(5, 2)` *(static)* | `(3, 3, 2, 2)` | Ratchets down `5 -> 3` (`decrement_by = 2`) | Extended with `SVN 3` |
| **3** | **Hitless Upgrade** (`FIRMWARE_LOAD` `SVN = 6`) | `6 >= max(2, 2)` → **Accepted** | `(5, 2)` *(static)* | `(6, 3, 2, 2)` | Stays `3` (`min(3, 6) = 3`) | Extended with `SVN 6` |
| **4** | **Advance Soft ARB** (`INCREASE_FW_SOFT_SVN(4)`) | `2 <= 4 <= 6` → **Accepted** | `(5, 2)` *(static)* | `(6, 3, 2, 4)` *(re-signed by FMC)* | Stays `3` | **Unchanged** (same image) |
| **5** | **Hitless Downgrade above Soft Floor** (`FIRMWARE_LOAD` `SVN = 5`) | `5 >= max(2, 4)` → **Accepted** | `(5, 2)` *(static)* | `(5, 3, 2, 4)` | Stays `3` (`min(3, 5) = 3`) | Extended with `SVN 5` |
| **6** | **Hitless Rollback below Soft Floor** (`FIRMWARE_LOAD` `SVN = 3`) | `3 < max(2, 4)` → **Rejected** | `(5, 2)` *(static)* | `(5, 3, 2, 4)` *(unchanged)* | Stays `3` | **Unchanged** |
| **7** | **Invalid Soft ARB > Active FW** (`INCREASE_FW_SOFT_SVN(6)` while at `SVN = 5`) | `6 > fw_svn(5)` → **Rejected** | `(5, 2)` *(static)* | `(5, 3, 2, 4)` *(unchanged)* | Stays `3` | **Unchanged** |
| **8** | **Invalid Soft ARB < Active Soft Floor** (`INCREASE_FW_SOFT_SVN(3)` when `soft_svn = 4`) | `3 < soft_svn(4)` → **Rejected** | `(5, 2)` *(static)* | `(5, 3, 2, 4)` *(unchanged)* | Stays `3` | **Unchanged** |
| **9** | **Warm Reset** (while running `SVN = 5`, `soft_svn = 4`) | `WarmResetEntries` preserved → **Accepted** | `(5, 2)` *(static)* | `(5, 3, 2, 4)` *(preserved)* | Stays `3` | **Unchanged** |
| **10** | **Next Cold Boot** with FW `SVN = 5` (fuses still `2`) | `5 >= max(2, 2)` → **Accepted** | `(5, 2)` | `(5, 5, 2, 2)` *(`min_svn` & `soft_svn` reset)* | Re-initialized to `5` | Reset & extended with `SVN 5` |

### 6.2 Detailed Explanation of Key Transitions

* **Step 1 (Cold Boot at `SVN = 5`)**:
  ROM initializes `cold_boot_fw_svn = 5`, `fw_svn = 5`, `fw_min_svn = 5`, and `fw_soft_svn = effective_fuse_svn = 2`. The hardware key ladder is initialized to `SVN = 5`. Both the FMC Alias certificate (`(5, 2)`) and the initial RT Alias certificate (`(5, 5, 2, 2)`) reflect the cold-boot state.
* **Step 2 (Hitless Downgrade to `SVN = 3`)**:
  Because `fw_soft_svn` is still `2`, rolling back from `SVN 5` to `SVN 3` is permitted (`3 >= max(2, 2)`). ROM updates `fw_svn = 3` and `fw_min_svn = min(5, 3) = 3`, and extends the hardware key ladder by `5 - 3 = 2` steps so `SVN 3` cannot derive `SVN 5` secrets. The FMC Alias certificate remains static at `(5, 2)`.
* **Step 3 (Hitless Upgrade to `SVN = 6`)**:
  ROM verifies `6 >= max(2, 2)` and updates `fw_svn = 6`. Crucially, `fw_min_svn` remains `min(3, 6) = 3` because the hardware key ladder is a one-way KDF within a boot cycle and cannot be ratcheted back up without a Cold Reset.
* **Step 4 (Advancing Soft ARB to `4` via `INCREASE_FW_SOFT_SVN(4)`)**:
  After qualifying `SVN >= 4`, the operator issues `INCREASE_FW_SOFT_SVN(4)`. ROM verifies `fw_soft_svn (2) <= 4 <= fw_svn (6)` and commits `fw_soft_svn = 4`. No firmware image is loaded, so `PCR2` and `PCR3` are not extended, and the RT Alias key pair is unchanged. FMC re-signs the RT Alias certificate with `(6, 3, 2, 4)`.
* **Steps 5 & 6 (Downgrade Enforcement after Soft ARB Advance)**:
  With `fw_soft_svn = 4`, a hitless update to `SVN = 5` succeeds (`5 >= 4`), whereas an attempt to roll back to `SVN = 3` is rejected by ROM (`3 < 4`) even though `3 >= fw_fuse_svn (2)`. On rejection, ROM leaves `DataVault::WarmResetEntries` untouched and returns to the running `SVN = 5` image.
* **Steps 7 & 8 (Invalid `INCREASE_FW_SOFT_SVN` Requests)**:
  * Requesting `soft_svn = 6` while `fw_svn = 5` is rejected (`requested > fw_svn`) so ROM never commits a floor that would immediately invalidate the currently running firmware.
  * Requesting `soft_svn = 3` while `fw_soft_svn = 4` is rejected (`requested < fw_soft_svn`) because `fw_soft_svn` is strictly non-decreasing within a power cycle.
* **Step 9 (Warm Reset) vs. Step 10 (Cold Boot)**:
  * Across a **Warm Reset**, DCCM is retained, so `fw_svn = 5`, `fw_min_svn = 3`, and `fw_soft_svn = 4` remain active and enforced.
  * Across a **Cold Boot**, DCCM and the key ladder are re-initialized from hardware fuses. Unless the `CPTRA_CORE_RUNTIME_SVN` fuse was permanently burned in OTP prior to the Cold Boot, `fw_soft_svn` resets to `fw_fuse_svn (2)` and `fw_min_svn` resets to the newly booted image's SVN (`5`).

### 6.3 Special & Edge Cases

| Edge Case | Behavior & Reported Values |
| :--- | :--- |
| **Cold Boot at `SVN 3` → Hitless Upgrade to `SVN 6` → `INCREASE_FW_SOFT_SVN(6)`** | Even without any downgrade, Cold Boot at `SVN 3` sets `min_svn = 3`. Upgrading to `SVN 6` and advancing `soft_svn` to `6` yields RT Alias `(6, 3, 2, 6)`. `soft_svn` is constrained by `fw_svn` (`6`), **not** `min_svn` (`3`); otherwise an operator could never raise `soft_svn` above the cold-boot SVN after a hitless upgrade. |
| **Idempotent `INCREASE_FW_SOFT_SVN(4)` when `soft_svn == 4`** | **Accepted** (`4 >= 4` and `4 <= fw_svn`); RT Alias values remain `(fw_svn, min_svn, fuse_svn, 4)`. |
| **OTP Fuse Burned at Runtime (`fuse_svn: 2 -> 4`) before Cold Boot** | Hardware fuse registers in `soc_ifc` are latched only during Cold Reset prior to `CPTRA_FUSE_WR_DONE`. Both FMC Alias and RT Alias `fuse_svn` remain `2` for the remainder of the current boot cycle and update to `4` on the next Cold Boot. |
| **`Unprovisioned` Lifecycle or `anti_rollback_disable == 1`** | `effective_fuse_svn = 0`; Cold Boot initializes `fw_soft_svn = 0`, and `ImageVerifier::verify_svn()` bypasses floor enforcement while still enforcing `svn <= MAX_FIRMWARE_SVN (128)` for key-ladder bounds. |

---

## 7. Security Rationale: Why `fw_min_svn`, `fw_soft_svn`, `fw_svn`, and `fw_fuse_svn` Are All Needed

A key scenario to understand is when **`fw_min_svn < fw_soft_svn <= fw_svn`** (for example, Step 4 above where `min_svn = 3`, `soft_svn = 4`, and `fw_svn = 6`). Each value answers a distinct security question for the relying party / verifier:

1. **Why `fw_min_svn` Remains Essential Even When `fw_soft_svn > fw_min_svn`:**
   * **Preventing the Masking Attack (No Clean State Since `min_svn` Executed):**
     Hitless updates (`FIRMWARE_LOAD`) do **not** clear DCCM, DPE contexts, or Key Vault slots. If `SVN 3` contained a state-corrupting or key-exposure vulnerability, an attacker who compromised `SVN 3` while it was running could hitlessly upgrade to `SVN 6` and advance `fw_soft_svn` to `4` (or `6`). Reporting `fw_min_svn = 3` ensures the verifier always sees that `SVN 3` executed during the current power cycle without a clean Cold Reset.
   * **Disambiguating Hot Patches from Cold-Boot Mitigations:**
     If a vulnerability fixed in `SVN 4+` requires cold-boot initialization (or FMC/ROM state re-initialization) to take effect, hitlessly updating from `SVN 3` to `SVN 6` does not apply the cold-boot mitigation. `fw_min_svn = 3` proves the platform only hot-patched and has not yet cold-booted into `SVN >= 4`.
   * **Cryptographic Key-Ladder Strength:**
     Caliptra's hardware key ladder can only ratchet downward during a boot cycle (`decrement_by`). Even after upgrading to `SVN 6` and raising `fw_soft_svn` to `4`, the active key-ladder secrets remain at `fw_min_svn = 3` derivation strength—meaning `SVN 3` could derive the same key-ladder secrets that `SVN 6` holds now until a Cold Boot resets the key ladder.
2. **Why `fw_soft_svn` Is Essential Alongside `fw_min_svn`:**
   * `fw_min_svn` is a historical minimum (`min(old_min_svn, new_svn)`) and **not** an enforcement floor. Without `fw_soft_svn`, a platform running `SVN 6` with `fw_fuse_svn = 2` could be silently rolled back to `SVN 2` right after attestation.
   * `fw_soft_svn = 4` provides a ROM-enforced guarantee that for the remainder of the power cycle, no firmware image with `SVN < 4` can be loaded via `FIRMWARE_LOAD`.
3. **Verifier Policy Evaluation:**
   * If a relying party's policy only requires that the currently running firmware is `>= 4` and cannot roll back below `4` (e.g., `SVN 3` had no persistent-state/key-leak CVE), checking `fw_svn >= 4` and `fw_soft_svn >= 4` is sufficient.
   * If `SVN 3` had a severe CVE requiring a full reset of volatile state and key-ladder secrets, the relying party checks `fw_min_svn >= 4`, sees `fw_min_svn = 3`, and requires a Cold Boot before releasing secrets.

---

## 8. System-Wide ARB Enforcement & Attestation Overview (Core FW to MCU RT)

Caliptra enforces and attests anti-rollback across four distinct component tiers:

| Tier | Component(s) Covered | Manifest SVN Field | Hardware Fuse Floor | Volatile / Soft ARB Mechanism | Where Enforced | Where Attested |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Caliptra Core FW Package** | FMC + Caliptra Runtime (single unified SVN for the Core FW bundle) | `ImageManifest.header.svn` (`u32`, `0..=128`) | `CPTRA_CORE_RUNTIME_SVN` (`soc_ifc.fuse_bank().fw_fuse_svn()`, 128-bit one-hot) | `fw_soft_svn` in `DataVault::WarmResetEntries` (`0..=128`, advanced via `INCREASE_FW_SOFT_SVN`) | **Caliptra ROM** (`ImageVerifier::verify_svn`: `svn >= max(fw_fuse_svn, fw_soft_svn)`) on Cold Boot & `FIRMWARE_LOAD` | **FMC Alias Cert**: `cold_boot_fw_svn`, `fw_fuse_svn` (static)<br>**RT Alias Cert**: `fw_svn`, `fw_min_svn`, `fw_fuse_svn`, `fw_soft_svn` (dynamic)<br>**`FW_INFO` / DPE `RTJM`**: `fw_svn`, `fw_min_svn` |
| **2. Vendor + Owner SoC Auth Manifest** | SoC Manifest Bundle (authorizes MCU RT `fw_id = 2` & SoC component metadata) | `AuthManifestPreamble.svn` (`u32`, `0..=128`) | `CPTRA_CORE_SOC_MANIFEST_SVN` (`soc_ifc.fuse_bank().soc_manifest_fuse_svn()`, 128-bit one-hot) | `max_soc_manifest_svn` flag (`AuthManifestFlags::MAX_SOC_MANIFEST_SVN`): when set, locks floor to `128` in `PersistentData` | **Caliptra Runtime** (`SetAuthManifestCmd::verify_preamble`: `svn >= soc_manifest_fuse_svn`) and **MCU ROM** (`verify_caliptra_svn`) | **DPE (`SOMV` / `0x534F4D56`)**: `tcb_info_svn = auth_manifest.preamble.svn` extended by Caliptra Runtime |
| **3. Owner Auth Manifest** | Standalone Owner SoC Manifest (`SET_OWNER_AUTH_MANIFEST`) | `OwnerAuthManifestPreamble.svn` (`u32`, `0..=128`) | *TODO in `runtime/src/set_owner_auth_manifest.rs:106` (`// TODO: Check SVN`)* | None currently | **Caliptra Runtime** (`SetOwnerAuthManifestCmd::verify_owner_manifest`) | **DPE (`SOMO` / `0x534F4D4F`)**: `tcb_info_svn = owner_manifest.preamble.svn` extended by Caliptra Runtime |
| **4. MCU RT & SoC Images** | MCU Runtime (`MCU_IMAGE_ID = 2`) and SoC Component Images (`fw_id >= 3`) | `McuImageHeader.svn` (`u16`) + `McuComponentSvnManifest` (`min_svn`, `soc_image_min_svn[i]`) | OTP fuses (`OTP_CPTRA_CORE_RUNTIME_SVN`, `OTP_CPTRA_CORE_SOC_MANIFEST_SVN`, `MCU_COMPONENT_SVN_MANIFEST_MIN_SVN`, `SOC_IMAGE_MIN_SVN[i]`) | Optional `burn_caliptra_owned_svns()` in MCU ROM ratchets OTP fuses up to match running SVN | **MCU ROM** (`verify_mcu_svn`, `verify_soc_image_svn`, `verify_caliptra_svn`) & **Caliptra Runtime** (`AUTHORIZE_AND_STASH` / `ACTIVATE_FIRMWARE`) | **DPE (`MCFW` / `0x4D434657`)** for MCU RT + **`STASH_MEASUREMENT`** (`metadata = svn`) for SoC components |

---

## 9. Summary of Code Changes by File

| Crate / File | Change Summary |
| :--- | :--- |
| `drivers/src/data_vault.rs` | Add `pub(crate) fw_soft_svn: u32` to `WarmResetEntries` and `fw_soft_svn()` / `set_fw_soft_svn(val: u32)` accessors on `DataVault`. |
| `drivers/src/persistent.rs` | Adjust `ROM_DATA_RESERVED1_1_SIZE` by `-4` bytes to account for `WarmResetEntries::fw_soft_svn` (0 net DCCM change). |
| `common/src/verifier.rs` | Implement `fn fw_soft_svn(&mut self) -> u32` on `FirmwareImageVerificationEnv` returning `self.data_vault.fw_soft_svn()`. |
| `image/verify/src/lib.rs` & `verifier.rs` | Add `fn fw_soft_svn(&mut self) -> u32` to `ImageVerificationEnv`; update `ImageVerifier::verify_svn()` to enforce `fw_svn >= max(self.env.fw_fuse_svn(), self.env.fw_soft_svn())`. |
| `rom/dev/src/flow/cold_reset/fw_processor/mod.rs` | In `populate_data_vault()`, initialize `data_vault.set_fw_soft_svn(info.effective_fuse_svn)`. |
| `rom/dev/src/flow/update_reset.rs` | Dispatch `actual_cmd`: keep `CommandId::FIRMWARE_LOAD` path and add `CommandId::INCREASE_FW_SOFT_SVN` handler (`handle_increase_fw_soft_svn`); preserve `UpdateResetComplete` if pre-mutation verification fails. |
| `api/src/mailbox.rs` | Define `CommandId::INCREASE_FW_SOFT_SVN` and `IncreaseFwSoftSvnReq`. |
| `runtime/src/lib.rs` & `runtime/src/update.rs` | Handle `CommandId::INCREASE_FW_SOFT_SVN`: enforce `ensure_pl0()`, validate request checksum and advisory bounds, leave mailbox txn open, and call `handle_impactless_update()`. |
| `fmc/src/hand_off.rs` & `fmc/src/flow/rt_alias.rs` | Expose `HandOff::fw_soft_svn(env)` / `HandOff::fw_min_svn(env)` / `HandOff::fw_fuse_svn(env)` and populate the RT Alias X.509 TCB Info fields. |
| `x509/gen/src/*` & `x509/src/*` | Update RT Alias certificate template to encode the agreed SVN fields (`fw_svn`, `fw_min_svn`, `fw_fuse_svn`, `fw_soft_svn`). |

