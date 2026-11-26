# Issue #4318: FMC Alias Certificate, ROM Cold-Boot Flow, and `FW_INFO_EXT` Design Specification

* **Issue Reference**: [`chipsalliance/caliptra-sw#4318` — Field Entropy Provisioning State Tracking & Attestation Options](https://github.com/chipsalliance/caliptra-sw/issues/4318)
* **Target Hardware / ROM Revision**: Caliptra 2.2 (`caliptra-2.2-dev` / `main`)
* **Scope**: Caliptra Core ROM, FMC, Common (DICE / UDS-FE / X.509), Runtime (`FW_INFO_EXT`), and MCU OCP EAT Integration

---

## 1. Executive Summary & Why ROM Must Perform These Changes

### 1.1 Architectural Alignment Summary

Per the alignment in [`chipsalliance/caliptra-sw#4318`](https://github.com/chipsalliance/caliptra-sw/issues/4318) and the attestation architecture review:

1. **Hybrid `CALIPTRA_2_X_FUSE_OWNER_INFO` Reporting in FMC Alias Certificate**:
   * **`TcbInfo.vendorInfo` (Raw Security-Critical & Per-Chip/Ratcheting State)**: Reports the raw security-critical fuse and provisioning state directly in the `CALIPTRA_2_X_FUSE_OWNER_INFO` `TcbInfo` entry so a standalone DICE verifier can immediately appraise anti-rollback disable status, key-revocation bitmasks, minimum fused SVNs, and per-partition Field Entropy (FE) status without parsing an external token.
   * **`TcbInfo.fwids[0]` (Comprehensive SHA-384 Digest)**: Continues to hash the **entire** `CALIPTRA_2_X_FUSE_OWNER_INFO` structure (both fleet-wide owner configuration and the security-critical status fields, including the cold-boot FE status snapshot).
2. **Symmetric TCB Structures for Direct Digest Reconstruction**:
   * Each FMC TCB info structure (`CALIPTRA_2_X_FUSE_OWNER_INFO` and `CALIPTRA_2_X_FUSE_VENDOR_INFO`) uses a consistent class identifier (`tcb_type` in X.509 `MultiTcbInfo` and `class_id` in OCP EAT Concise Evidence).
   * The raw structure reported via `FW_INFO_EXT` (and carried in OCP EAT) matches the exact byte layout hashed by ROM to compute `fwids[0]`, allowing verifiers to hash the reported structure directly and compare it 1:1 against `fwids[0]` in the FMC Alias certificate.
3. **Cold-Boot Snapshot Semantics**:
   * Field Entropy programming (`FE_PROG`) or fuse updates performed during runtime do **not** alter the current boot cycle's `LDevID` or `FMC Alias` certificate; they take effect on the next Cold Boot.
   * Therefore, ROM captures a frozen **cold-boot snapshot** of the 4 FE partition states during Cold Reset and stores it in `DataVault::ColdResetEntries`.

### 1.2 Why These Changes Must Be Executed by Caliptra ROM

Yes—**Caliptra ROM is required** to implement the FMC Alias and FE snapshot changes for four fundamental reasons:

1. **ROM Generates and Signs the FMC Alias Certificates**:
   * Both `FmcAliasCertTbsEcc384` and `FmcAliasCertTbsMlDsa87` are constructed and signed by `FmcAliasLayer::derive()` in **ROM** (`rom/dev/src/flow/cold_reset/fmc_alias.rs:82-92`) during Cold Boot before `LDevID` signing keys are erased from the Key Vault.
2. **ROM Extends `PCR0` (`PCR_ID_FMC_CURRENT`) and `PCR1` (`PCR_ID_FMC_JOURNEY`)**:
   * `FMC_CDI` (`KEY_ID_ROM_FMC_CDI` in `KV6`) is derived from `PCR0` in ROM (`rom/dev/src/flow/cold_reset/fmc_alias.rs:47-51`).
   * ROM enforces the invariant (`rom/dev/src/pcr.rs:94-95` and `common/src/dice.rs:203-204`) that `PCR0`/`PCR1` `DeviceStatus` and the FMC Alias `TcbInfo` extensions must measure the exact same device state.
3. **Cold-Boot FE Snapshot Must Be Latched Before Runtime Can Run `FE_PROG`**:
   * Because Runtime can execute `FE_PROG` mid-boot—changing live OTP DAI metadata without changing the already-issued FMC Alias certificate—ROM must read the 4 FE partitions' status at Cold Boot and lock that snapshot in `DataVault::ColdResetEntries` (protected Read-Only by `pmp1cfg`).
   * FMC (`fmc/src/flow/fmc_alias_csr.rs`, which builds the FMC Alias CSR on Cold Boot) and Runtime (`FW_INFO_EXT`) then read the frozen cold-boot FE status from `DataVault::ColdResetEntries` so the CSR and EAT claims always match the ROM-signed FMC Alias certificate.
4. **`UdsFeProgrammingFlow::fe_status()` Is Currently Restricted to `#[cfg(feature = "runtime")]`**:
   * In `common/src/uds_fe_programming.rs:73,128`, `OtpCtrlConfig::read_metadata()` and `UdsFeProgrammingFlow::fe_status()` are currently compiled only when `feature = "runtime"` is enabled. Removing that gate makes the OTP DAI metadata reader available to ROM during Cold Reset.

---

## 2. Canonical TCB Structures for `FMC_ALIAS` and OCP EAT

To guarantee that verifiers can reconstruct `fwids[0]` directly without field-by-field reassembly bugs, `caliptra_common` (or `caliptra_api`) should define canonical `#[repr(C)]` byte structures used identically by ROM, FMC, Runtime (`FW_INFO_EXT`), and OCP EAT.

### 2.1 `FmcAliasOwnerDeviceInfo` (`CALIPTRA_2_X_FUSE_OWNER_INFO`)

The owner TCB structure is partitioned into two contiguous sub-structures:
1. **`FmcAliasOwnerConfig` (50 bytes)**: Fleet-wide owner configuration.
2. **`FmcAliasOwnerSecurityState` (10 bytes)**: Security-critical / ratcheting / per-chip state placed raw in `TcbInfo.vendorInfo`.

```rust
/// Security-critical and per-chip/ratcheting owner state (10 bytes).
/// Placed raw in FMC_ALIAS `CALIPTRA_2_X_FUSE_OWNER_INFO` `TcbInfo.vendorInfo`
/// AND included in the comprehensive SHA-384 digest (`TcbInfo.fwids[0]`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FmcAliasOwnerSecurityState {
    /// Anti-rollback disable fuse (0 = enabled, 1 = disabled)
    pub anti_rollback_disable: u8,
    /// Vendor ECC public-key revocation bitmask (4 bits in u8)
    pub vendor_ecc_pub_key_revocation: u8,
    /// Vendor LMS public-key revocation bitmask (little-endian u32)
    pub vendor_lms_pub_key_revocation: [u8; 4],
    /// Vendor ML-DSA public-key revocation bitmask (4 bits in u8)
    pub vendor_mldsa_pub_key_revocation: u8,
    /// Caliptra Core FW minimum SVN fuse (`CPTRA_CORE_RUNTIME_SVN`, 0..=128)
    pub fw_fuse_svn: u8,
    /// SoC Authorization Manifest minimum SVN fuse (`CPTRA_CORE_SOC_MANIFEST_SVN`, 0..=128)
    pub soc_manifest_fuse_svn: u8,
    /// Cold-boot Field Entropy status across all 4 partitions (little-endian u16;
    /// Partition i occupies bits [2*i+1 : 2*i] as `FePartitionStatus`, bits 15:8 = 0)
    pub field_entropy_status: [u8; 2],
}

/// Complete `CALIPTRA_2_X_FUSE_OWNER_INFO` input structure (60 bytes total).
/// SHA-384(`FmcAliasOwnerDeviceInfo::as_bytes()`) == `TcbInfo.fwids[0]`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FmcAliasOwnerDeviceInfo {
    /// Effective Owner Public Key Hash from `data_vault.owner_pk_hash()` (48 bytes)
    pub owner_pk_hash: [u8; 48],
    /// 1 if `CPTRA_OWNER_PK_HASH` is programmed in fuses (`!= 0`), 0 if from image header
    pub owner_pk_hash_in_fuses: u8,
    /// SoC Authorization Manifest maximum SVN fuse (`max_soc_manifest_fuse_svn`, 1 byte)
    pub max_soc_manifest_fuse_svn: u8,
    /// Raw security-critical & per-chip/ratcheting state (10 bytes, also in `TcbInfo.vendorInfo`)
    pub security_state: FmcAliasOwnerSecurityState,
}
```

#### Field Placement Matrix for `CALIPTRA_2_X_FUSE_OWNER_INFO`

| Field | Size | Category | `FMC_ALIAS` `TcbInfo.fwids[0]` (SHA-384) | `FMC_ALIAS` `TcbInfo.vendorInfo` (Raw 10 B) | `FW_INFO_EXT` / MCU OCP EAT (Raw) |
| :--- | :---: | :--- | :---: | :---: | :---: |
| `owner_pk_hash` (`data_vault.owner_pk_hash()`) | `48 B` | Owner configuration (fleet-wide) | Yes | — | Yes |
| `owner_pk_hash_in_fuses` (`CPTRA_OWNER_PK_HASH != 0`) | `1 B` | Owner configuration (fleet-wide) | Yes | — | Yes |
| `max_soc_manifest_fuse_svn` | `1 B` | Owner configuration (fleet-wide) | Yes | — | Yes |
| `anti_rollback_disable` | `1 B` | Security-critical state | Yes | Yes | Yes |
| `vendor_ecc_pub_key_revocation` | `1 B` | Security-critical / ratcheting state | Yes | Yes | Yes |
| `vendor_lms_pub_key_revocation` | `4 B` (LE) | Security-critical / ratcheting state | Yes | Yes | Yes |
| `vendor_mldsa_pub_key_revocation` | `1 B` | Security-critical / ratcheting state | Yes | Yes | Yes |
| `fw_fuse_svn` (min SVN) | `1 B` | Security-critical / ratcheting state | Yes | Yes | Yes |
| `soc_manifest_fuse_svn` (min SVN) | `1 B` | Security-critical / ratcheting state | Yes | Yes | Yes |
| `field_entropy_status` (4 partitions × 2 bits) | `2 B` (LE) | Security-critical / per-chip state | Yes | Yes | Yes |
| **Total** | **`60 B`** | | **48 B SHA-384** | **10 B Raw** | **60 B Raw** |

> **Why all 60 bytes are included in `FW_INFO_EXT` / EAT**: As aligned in `#4318` (comment `#issuecomment-6535238462`), keeping the full 60-byte `FmcAliasOwnerDeviceInfo` structure intact allows an EAT verifier to compute `SHA-384(owner_device_info)` in a single pass and match `TcbInfo.fwids[0]` directly without cherry-picking fields.

---

### 2.2 `FmcAliasVendorDeviceInfo` (`CALIPTRA_2_X_FUSE_VENDOR_INFO`)

Similarly, the vendor TCB structure is defined as a fixed 55-byte `#[repr(C)]` struct whose SHA-384 digest equals `CALIPTRA_2_X_FUSE_VENDOR_INFO` `TcbInfo.fwids[0]`:

```rust
/// Complete `CALIPTRA_2_X_FUSE_VENDOR_INFO` input structure (55 bytes total).
/// SHA-384(`FmcAliasVendorDeviceInfo::as_bytes()`) == `TcbInfo.fwids[0]`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FmcAliasVendorDeviceInfo {
    /// Vendor Public Key Info Hash fuse (`CPTRA_VENDOR_PK_HASH`, 48 bytes)
    pub vendor_pub_key_info_hash: [u8; 48],
    /// Fused PQC key type (`soc_ifc.fuse_bank().pqc_key_type()`, 1 byte)
    pub pqc_key_type: u8,
    /// Device lifecycle state (`soc_ifc.lifecycle()`, 1 byte)
    pub lifecycle: u8,
    /// Debug locked state (`soc_ifc.debug_locked()`, 1 byte)
    pub debug_locked: u8,
    /// Image bundle FW SVN from Cold Boot (`data_vault.cold_boot_fw_svn()`, 1 byte)
    pub cold_boot_fw_svn: u8,
    /// Active Vendor ECC public key index (`data_vault.vendor_ecc_pk_index()`, 1 byte)
    pub vendor_ecc_pk_index: u8,
    /// Active Vendor PQC public key index (`data_vault.vendor_pqc_pk_index()`, 1 byte)
    pub vendor_pqc_pk_index: u8,
    /// Subsystem mode enabled (`soc_ifc.subsystem_mode()`, 1 byte)
    pub subsystem_mode: u8,
}
```

---

## 3. Detailed ROM & Firmware Changes for `FMC_ALIAS` (Issue #4318)

### 3.1 Step 1 — Enable `UdsFeProgrammingFlow::fe_status()` in ROM (`common/src/uds_fe_programming.rs`)

Currently, `OtpCtrlConfig::read_metadata()` (`common/src/uds_fe_programming.rs:73`) and `UdsFeProgrammingFlow::fe_status()` (`common/src/uds_fe_programming.rs:128`) are gated with `#[cfg(feature = "runtime")]`.

* **Change**:
  * Remove `#[cfg(feature = "runtime")]` from `ZEROIZATION_MARKER_THRESHOLD`, `DAI_READ_TIMEOUT_CYCLES`, `DIRECT_ACCESS_REGWEN_MASK`, `SECRET_DIGEST_READ_LOCK_OFFSET`, `OtpCtrlConfig::read_metadata()`, and `UdsFeProgrammingFlow::fe_status()`.
  * Add a helper `UdsFeProgrammingFlow::fe_status_all(soc_ifc: &SocIfc, dma: &Dma) -> u16` that iterates `partition in 0..FE_MAX_PARTITIONS` and packs each 2-bit `FePartitionStatus` into bits `[2*i+1 : 2*i]` of a `u16` (`0x00FF` when not in subsystem mode or if inaccessible).

### 3.2 Step 2 — Latch Cold-Boot FE Status in `DataVault::ColdResetEntries` (`drivers/src/data_vault.rs`)

Because `FmcAliasCsr` (generated in FMC) and `FW_INFO_EXT` (executed in Runtime) must report the exact cold-boot FE status that ROM measured into `FMC_ALIAS`—even if `FE_PROG` is later called at runtime—ROM must persist the cold-boot FE status in `DataVault::ColdResetEntries`.

* **Change**:
  * Add `pub(crate) cold_boot_fe_status: u32` to `ColdResetEntries` in `drivers/src/data_vault.rs` (reducing `ROM_DATA_RESERVED1_0_SIZE` in `drivers/src/persistent.rs` by 4 bytes so net DCCM footprint change is **0 bytes**).
  * In `FirmwareProcessor::process()` (`rom/dev/src/flow/cold_reset/fw_processor/mod.rs`), during Cold Boot before `pcr::extend_pcrs()`:
    ```rust
    let cold_boot_fe_status = UdsFeProgrammingFlow::fe_status_all(&env.soc_ifc, &env.dma) as u32;
    env.persistent_data
        .get_mut()
        .rom
        .data_vault
        .set_cold_boot_fe_status(cold_boot_fe_status);
    ```
  * When `lock_cold_reset_reg()` runs at the end of Cold Boot (and at the start of every Warm/Update Reset), `cold_boot_fe_status` is hardware-locked Read-Only via RISC-V PMP (`pmp1cfg`).

### 3.3 Step 3 — Include Cold-Boot FE Status in `PCR0` and `PCR1` (`rom/dev/src/pcr.rs`)

`rom/dev/src/pcr.rs:94-95` states:
> `// NOTE: The contents of this PCR and the FMC Alias TCB info must stay in sync.`

* **Change**:
  * In `rom/dev/src/pcr.rs:extend_pcrs()`, extend `device_status` from `[u8; 18]` to `[u8; 20]` by appending `cold_boot_fe_status_le_bytes[0]` and `cold_boot_fe_status_le_bytes[1]` (the 2-byte little-endian `field_entropy_status` from `data_vault.cold_boot_fe_status() as u16`).
  * Because `PcrLogEntry.pcr_data` is `[u32; 12]` (48 bytes), increasing `PcrLogEntryId::DeviceStatus` from 18 bytes to 20 bytes fits well within the existing 48-byte `PcrLogEntry` slot with zero extra RAM usage.

### 3.4 Step 4 — Update `common/src/dice.rs` Builders and Hash Functions

* **Change**:
  * Add `pub fn fmc_alias_owner_device_info(soc_ifc: &SocIfc, data_vault: &DataVault) -> FmcAliasOwnerDeviceInfo` and `pub fn fmc_alias_vendor_device_info(soc_ifc: &SocIfc, data_vault: &DataVault) -> FmcAliasVendorDeviceInfo` in `common/src/dice.rs`.
  * Update `gen_fmc_alias_owner_device_info_hash()` to hash `fmc_alias_owner_device_info(soc_ifc, data_vault).as_bytes()` using SHA-384.
  * Update `gen_fmc_alias_vendor_device_info_hash()` to hash `fmc_alias_vendor_device_info(soc_ifc, data_vault).as_bytes()` using SHA-384.

### 3.5 Step 5 — Add `vendorInfo` to `CALIPTRA_2_X_FUSE_OWNER_INFO` in X.509 Templates (`x509/gen/`)

In `x509/gen/src/x509.rs:make_fmc_dice_tcb_info_ext()`:

* **Current**:
  ```rust
  let owner_device_info = TcbInfo {
      vendor: None,
      model: None,
      version: None,
      svn: None,
      layer: None,
      index: None,
      fwids: Some(asn1::SequenceOfWriter::new(&owner_device_asn1_fwids)),
      flags: None,
      vendor_info: None,
      tcb_type: Some(b"CALIPTRA_2_X_FUSE_OWNER_INFO"),
      flags_mask: None,
  };
  ```
* **New**:
  * Pass a 10-byte placeholder slice `owner_vendor_info: &[u8; 10]` (e.g., `&[0xA5; 10]`) into `make_fmc_dice_tcb_info_ext()` and set `vendor_info: Some(owner_vendor_info)` on `owner_device_info`.
  * Register a template parameter `TCB_INFO_OWNER_DEVICE_VENDOR_INFO` (length `10` bytes) in `CertTemplateBuilder::add_fmc_dice_tcb_info_ext()` (`x509/gen/src/cert.rs`) and `CsrTemplateBuilder::add_fmc_dice_tcb_info_ext()` (`x509/gen/src/csr.rs`).
  * Regenerate `FmcAliasCertTbsEcc384`, `FmcAliasCertTbsMlDsa87`, `FmcAliasCsrTbsEcc384`, and `FmcAliasTbsMlDsa87` via `cargo run -p caliptra-x509-gen` (+12 bytes in DER TBS size: 2-byte ASN.1 `[8] IMPLICIT OCTET STRING` tag/length + 10-byte payload, which fits within the existing `ecc_fmcalias_tbs` / `mldsa_fmcalias_tbs` buffers in `RomPersistentData`).
  * In `rom/dev/src/flow/cold_reset/fmc_alias.rs` (`generate_cert_sig_ecc` and `generate_cert_sig_mldsa`) and `fmc/src/flow/fmc_alias_csr.rs` (`make_ecc_csr` and `make_mldsa_csr`), populate:
    ```rust
    let owner_info = dice::fmc_alias_owner_device_info(soc_ifc, data_vault);
    // ...
    tcb_info_owner_device_vendor_info: owner_info.security_state.as_bytes().try_into().unwrap(),
    ```

---

## 4. Designing `FW_INFO_EXT` as an Extension of `FW_INFO`

### 4.1 Why `FW_INFO` Alone Is Insufficient for Verifiers & OCP EAT

Inspecting `FwInfoResp` (`api/src/mailbox.rs:2045-2073`) against the inputs to `CALIPTRA_2_X_FUSE_OWNER_INFO`, `CALIPTRA_2_X_FUSE_VENDOR_INFO`, and RFC #687 Soft ARB reveals three gaps:

1. **Missing Fuse & Security-State Fields Needed to Reconstruct `FMC_ALIAS` `fwids[0]`**:
   * **Missing from `CALIPTRA_2_X_FUSE_OWNER_INFO`**:
     * `owner_pk_hash_in_fuses` (`CPTRA_OWNER_PK_HASH != 0`)
     * `anti_rollback_disable`
     * `vendor_ecc_pub_key_revocation`
     * `vendor_lms_pub_key_revocation`
     * `vendor_mldsa_pub_key_revocation`
     * `fw_fuse_svn` *(Note: `FwInfoResp.min_fw_svn` is `data_vault.fw_min_svn()`, the volatile minimum since cold boot—`FwInfoResp` does **not** report `soc_ifc.fuse_bank().fw_fuse_svn()`!)*
     * `max_soc_manifest_fuse_svn`
   * **Missing from `CALIPTRA_2_X_FUSE_VENDOR_INFO`**:
     * `fuse_pqc_key_type` *(Note: `FwInfoResp.image_manifest_pqc_type` reports `manifest1.pqc_key_type`, whereas `CALIPTRA_2_X_FUSE_VENDOR_INFO` hashes `soc_ifc.fuse_bank().pqc_key_type()`!)*
     * `lifecycle` (`soc_ifc.lifecycle()`)
     * `debug_locked` (`soc_ifc.debug_locked()`)
     * `subsystem_mode` (`soc_ifc.subsystem_mode()`)
2. **Live `fe_status` vs. Cold-Boot `field_entropy_status` Snapshot**:
   * `FwInfoResp.fe_status` calls `UdsFeProgrammingFlow::fe_status()` **live** at the time of the `FW_INFO` command.
   * If `FE_PROG` was executed during the current boot cycle, live `fe_status` will differ from the cold-boot `field_entropy_status` baked into the `FMC_ALIAS` certificate's `TcbInfo.fwids[0]` and `TcbInfo.vendorInfo`.
3. **Backward Compatibility of `FW_INFO` (`0x494E_464F`)**:
   * Existing callers in MCU ROM and MCU Runtime (`DeviceState::fw_info()` in `caliptra-libapi` and `mcu_caliptra_api::fw_info()`) enforce `size == size_of::<FwInfoResp>()` (`376` bytes). Modifying `FwInfoResp` in-place would break compatibility with existing 2.1/2.2 clients.

### 4.2 Recommended `FW_INFO_EXT` Design (`CommandId::FW_INFO_EXT`)

Define `CommandId::FW_INFO_EXT` (e.g., `0x494E_4658` / `"INFX"`) as a superset command whose response **embeds `FwInfoResp` at offset 0** and appends the canonical DICE TCB structures and Soft ARB state:

```rust
// CommandId in api/src/mailbox.rs
pub const FW_INFO_EXT: Self = Self(0x494E_4658); // "INFX"

#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FwInfoExtResp {
    /// Complete legacy `FW_INFO` response (includes `hdr: MailboxRespHeader` at offset 0
    /// and live `fe_status` at the end of `base`).
    pub base: FwInfoResp,

    /// Active Soft Anti-Rollback SVN floor (`data_vault.fw_soft_svn()`, RFC #687).
    pub fw_soft_svn: u32,

    /// Caliptra Core FW minimum SVN fuse (`soc_ifc.fuse_bank().fw_fuse_svn()`).
    pub fw_fuse_svn: u32,

    /// Canonical 60-byte cold-boot `CALIPTRA_2_X_FUSE_OWNER_INFO` structure.
    /// - `SHA-384(fmc_owner_device_info.as_bytes())` == `FMC_ALIAS` owner `TcbInfo.fwids[0]`
    /// - `fmc_owner_device_info.security_state` (10 B) == `FMC_ALIAS` owner `TcbInfo.vendorInfo`
    pub fmc_owner_device_info: FmcAliasOwnerDeviceInfo,

    /// Canonical 55-byte cold-boot `CALIPTRA_2_X_FUSE_VENDOR_INFO` structure.
    /// - `SHA-384(fmc_vendor_device_info.as_bytes())` == `FMC_ALIAS` vendor `TcbInfo.fwids[0]`
    pub fmc_vendor_device_info: FmcAliasVendorDeviceInfo,

    /// Explicit padding to maintain 4-byte alignment for mailbox DWORD transfers.
    pub reserved: [u8; 1],
}
impl Response for FwInfoExtResp {}
```

### 4.3 Key Advantages of This `FW_INFO_EXT` Layout

1. **Zero Code Duplication in Caliptra Runtime (`runtime/src/info.rs`)**:
   * `FwInfoExtCmd::execute()` simply calls `FwInfoCmd::populate(&drivers, &mut resp.base)?` to fill `resp.base`, then populates:
     ```rust
     resp.fw_soft_svn = handoff.fw_soft_svn();
     resp.fw_fuse_svn = drivers.soc_ifc.fuse_bank().fw_fuse_svn();
     resp.fmc_owner_device_info = dice::fmc_alias_owner_device_info(&drivers.soc_ifc, handoff.data_vault);
     resp.fmc_vendor_device_info = dice::fmc_alias_vendor_device_info(&drivers.soc_ifc, handoff.data_vault);
     ```
   * Because `dice::fmc_alias_owner_device_info()` and `dice::fmc_alias_vendor_device_info()` are the **exact same helper functions** called by ROM when generating `FMC_ALIAS`, it is impossible for `FW_INFO_EXT` and `FMC_ALIAS` to drift out of sync.
2. **Both Cold-Boot and Live FE Status Are Available**:
   * `resp.fmc_owner_device_info.security_state.field_entropy_status` provides the **frozen cold-boot FE status** that matches `FMC_ALIAS` (`TcbInfo.vendorInfo` and `TcbInfo.fwids[0]`).
   * `resp.base.fe_status` continues to provide the **live FE status** from OTP DAI so an operator that just executed `FE_PROG` can confirm the partition transitioned from `Unprovisioned` to `Provisioned` before triggering the next Cold Boot.
3. **1:1 Verifier Digest Reconstruction in MCU OCP EAT**:
   * When MCU builds the OCP EAT Concise Evidence token, it calls `FW_INFO_EXT` and emits two `EvidenceTripleRecord` measurements:
     * `class_id = "CALIPTRA_2_X_FUSE_OWNER_INFO"` → `mval.raw_value = Some(resp.fmc_owner_device_info.as_bytes())` (60 bytes)
     * `class_id = "CALIPTRA_2_X_FUSE_VENDOR_INFO"` → `mval.raw_value = Some(resp.fmc_vendor_device_info.as_bytes())` (55 bytes)
   * The relying party / verifier simply hashes `mval.raw_value` with SHA-384 and verifies:
     ```text
     SHA-384(mval.raw_value) == FMC_ALIAS.MultiTcbInfo[i].fwids[0]
     ```
     and then appraises individual fields in `FmcAliasOwnerDeviceInfo` / `FmcAliasVendorDeviceInfo` against Owner Policy and Vendor CoRIM.

---

## 5. End-to-End Verification Flow (ROM → FMC Alias → `FW_INFO_EXT` → OCP EAT)

```text
+-----------------------------------------------------------------------------------+
| 1. COLD BOOT (Caliptra ROM)                                                       |
|  - Reads 4 FE partitions via `UdsFeProgrammingFlow::fe_status_all()`              |
|  - Latches `cold_boot_fe_status` in `DataVault::ColdResetEntries` (PMP Read-Only) |
|  - Extends `PCR0` & `PCR1` `DeviceStatus` (20 B, including `cold_boot_fe_status`) |
|  - Builds `owner_info: FmcAliasOwnerDeviceInfo` (60 B) & `vendor_info` (55 B)     |
|  - Populates `FMC_ALIAS` `MultiTcbInfo`:                                          |
|      * `CALIPTRA_2_X_FUSE_OWNER_INFO`:                                            |
|          - `fwids[0]`   = SHA-384(owner_info [60 B])                              |
|          - `vendorInfo` = owner_info.security_state [10 B raw]                    |
|      * `CALIPTRA_2_X_FUSE_VENDOR_INFO`:                                           |
|          - `fwids[0]`   = SHA-384(vendor_info [55 B])                             |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 2. RUNTIME (`FW_INFO_EXT` Mailbox Command)                                        |
|  - Returns `FwInfoExtResp`:                                                       |
|      * `base: FwInfoResp` (includes live `fe_status`)                             |
|      * `fw_soft_svn` & `fw_fuse_svn`                                              |
|      * `fmc_owner_device_info` (60 B, using `data_vault.cold_boot_fe_status()`)   |
|      * `fmc_vendor_device_info` (55 B)                                            |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 3. MCU RUNTIME (OCP EAT Concise Evidence)                                         |
|  - Places `fmc_owner_device_info` (60 B) in `CALIPTRA_2_X_FUSE_OWNER_INFO`        |
|    `MeasurementValue.raw_value`                                                   |
|  - Places `fmc_vendor_device_info` (55 B) in `CALIPTRA_2_X_FUSE_VENDOR_INFO`      |
|    `MeasurementValue.raw_value`                                                   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| 4. VERIFIER APPRAISAL                                                             |
|  - Standalone DICE check: reads 10-byte `vendorInfo` from `FMC_ALIAS` directly    |
|    to verify `field_entropy_status`, `anti_rollback_disable`, revocations, SVNs.  |
|  - Full EAT check: computes `SHA-384(raw_value)` for Owner (60 B) & Vendor (55 B) |
|    and verifies exact match against `FMC_ALIAS` `fwids[0]`, then appraises all    |
|    unwrapped fields against Vendor CoRIM + Owner Policy.                          |
+-----------------------------------------------------------------------------------+
```

---

## 6. Summary of Code Changes by File

| Crate / File | Change Summary |
| :--- | :--- |
| `common/src/uds_fe_programming.rs` | Remove `#[cfg(feature = "runtime")]` from `OtpCtrlConfig::read_metadata()` and `UdsFeProgrammingFlow::fe_status()`; add `fe_status_all()` returning packed `u16`. |
| `drivers/src/data_vault.rs` & `persistent.rs` | Add `cold_boot_fe_status: u32` to `ColdResetEntries` (adjust `ROM_DATA_RESERVED1_0_SIZE` by `-4` bytes for 0 net DCCM change). |
| `rom/dev/src/flow/cold_reset/fw_processor/mod.rs` | Latch `UdsFeProgrammingFlow::fe_status_all()` into `data_vault.set_cold_boot_fe_status(...)` during Cold Boot. |
| `rom/dev/src/pcr.rs` | Append 2-byte `cold_boot_fe_status` to `device_status` (`[u8; 18]` → `[u8; 20]`) in `extend_pcrs()`. |
| `api/src/mailbox.rs` | Define `FmcAliasOwnerSecurityState` (10 B), `FmcAliasOwnerDeviceInfo` (60 B), `FmcAliasVendorDeviceInfo` (55 B), `CommandId::FW_INFO_EXT`, and `FwInfoExtResp`. |
| `common/src/dice.rs` | Add `fmc_alias_owner_device_info()` and `fmc_alias_vendor_device_info()` helpers; hash their `.as_bytes()` in `gen_fmc_alias_owner_device_info_hash()` and `gen_fmc_alias_vendor_device_info_hash()`. |
| `x509/gen/src/*` & `x509/src/*` | Add 10-byte `vendor_info` (`TCB_INFO_OWNER_DEVICE_VENDOR_INFO`) to `CALIPTRA_2_X_FUSE_OWNER_INFO` in `FMC_ALIAS` Cert and CSR templates. |
| `rom/dev/src/flow/cold_reset/fmc_alias.rs` & `fmc/src/flow/fmc_alias_csr.rs` | Populate `tcb_info_owner_device_vendor_info` from `owner_info.security_state.as_bytes()`. |
| `runtime/src/info.rs` & `runtime/src/lib.rs` | Implement `FwInfoExtCmd::execute()` returning `FwInfoExtResp` and wire `CommandId::FW_INFO_EXT` in Runtime mailbox dispatch. |
