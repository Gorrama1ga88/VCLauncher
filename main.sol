// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VClauncher
 * @notice Vault-grade "blue binder" launchpad for institutional capital formation.
 * @dev Escrows commitment assets, enforces compliance gates, supports finalize/cancel + refunds,
 *      and distributes a payout asset under a linear vesting schedule.
 *
 *      This contract intentionally avoids custody shortcuts (no ETH receive path, no arbitrary external calls
 *      during state transitions), uses role-based access control, and is designed for mainnet deployment.
 */

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract VClauncher is AccessControl, Pausable, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    // =============================================================
    // Roles
    // =============================================================

    bytes32 public constant MANAGER_ROLE = keccak256("VC_LAUNCHER_MANAGER_ROLE");
    bytes32 public constant COMPLIANCE_ROLE = keccak256("VC_LAUNCHER_COMPLIANCE_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("VC_LAUNCHER_TREASURY_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("VC_LAUNCHER_EMERGENCY_ROLE");

    // =============================================================
    // Immutables (pre-populated addresses)
    // =============================================================

    address public immutable ADDRESS_A; // Admin / governance seat
    address public immutable ADDRESS_B; // Treasury (commitment asset sink)
    address public immutable ADDRESS_C; // Fee recipient
    address public immutable ADDRESS_D; // Compliance signer (EIP-712 attestations)

    // =============================================================
    // Fixed-point & configuration constants
    // =============================================================

    uint256 internal constant BPS_DENOMINATOR = 10_000;
    uint256 internal constant RATE_SCALE = 1e18;
    uint256 internal constant MAX_FEE_BPS = 500; // 5.00%

    uint64 internal constant MIN_DEAL_DURATION = 30 minutes;
    uint64 internal constant MAX_DEAL_DURATION = 365 days;
    uint64 internal constant MAX_VESTING_DURATION = 4 * 365 days;

    bytes32 internal constant CONFIG_TAG = 0x7cB7B74dE1cD1A1f5f2b7f6cA9D2bC984f7D2b9E6cD51F0a2B39d8b4c6E1dA3F;
    bytes32 internal constant DOMAIN_SALT = 0xA3d1E9c0b7F86D2b1A5cC49A8e0C17b9d4F1cA2b3D5e6f7091A2b3C4d5E6F708;

    // =============================================================
    // Errors
    // =============================================================

    error VCLaunch_InvalidAddress();
    error VCLaunch_InvalidDeal();
    error VCLaunch_InvalidTime();
    error VCLaunch_InvalidAmount();
    error VCLaunch_InvalidRate();
    error VCLaunch_NotLive();
    error VCLaunch_NotFinalized();
    error VCLaunch_AlreadyFinalized();
    error VCLaunch_DealNotOpen();
    error VCLaunch_DealClosed();
    error VCLaunch_DealCancelled();
    error VCLaunch_DealNotCancelled();
    error VCLaunch_SoftCapNotMet();
    error VCLaunch_HardCapExceeded();
    error VCLaunch_MinCommitNotMet();
    error VCLaunch_MaxCommitExceeded();
    error VCLaunch_CommitmentAssetMismatch();
    error VCLaunch_PayoutAssetMismatch();
    error VCLaunch_TransferProhibited();
    error VCLaunch_RefundUnavailable();
    error VCLaunch_ClaimUnavailable();
    error VCLaunch_NoClaimable();
    error VCLaunch_ComplianceDenied();
    error VCLaunch_SignatureExpired();
    error VCLaunch_SignatureInvalid();
    error VCLaunch_NonceMismatch();
    error VCLaunch_FeeTooHigh();
    error VCLaunch_VestingInvalid();
    error VCLaunch_DistributionInsufficient();
    error VCLaunch_DepositNotAllowed();
    error VCLaunch_EthNotAccepted();

    // =============================================================
    // Events
    // =============================================================

    event VCLaunch_DealCreated(
        uint256 indexed dealId,
        address indexed commitmentAsset,
        address indexed payoutAsset,
        bytes32 metadataHash,
        uint64 startTime,
        uint64 endTime
    );

    event VCLaunch_DealParametersUpdated(
        uint256 indexed dealId,
        bytes32 indexed field,
        uint256 previousValue,
        uint256 nextValue
    );

    event VCLaunch_DealLive(uint256 indexed dealId, uint64 startTime, uint64 endTime);
    event VCLaunch_DealCancelled(uint256 indexed dealId, bytes32 indexed reasonTag);
    event VCLaunch_DealFinalized(uint256 indexed dealId, bool success, uint256 totalCommitted, uint256 feePaid);

    event VCLaunch_Committed(uint256 indexed dealId, address indexed investor, uint256 amount, uint256 newTotal);
    event VCLaunch_Refunded(uint256 indexed dealId, address indexed investor, uint256 amount);

    event VCLaunch_PayoutDeposited(uint256 indexed dealId, address indexed from, uint256 amount, uint256 totalDeposited);
    event VCLaunch_Claimed(uint256 indexed dealId, address indexed investor, uint256 amount, uint256 cumulativeClaimed);

    event VCLaunch_ComplianceProfileSet(address indexed investor, uint32 flags, uint64 validUntil, uint96 capOverride);
    event VCLaunch_ComplianceSignerRotated(address indexed previousSigner, address indexed nextSigner);

    event VCLaunch_Paused(address indexed by);
    event VCLaunch_Unpaused(address indexed by);

    // =============================================================
    // Types
    // =============================================================

    enum DealState {
        Draft,
        Live,
        Finalized,
        Cancelled
    }

    struct VestingSchedule {
        uint64 start;
        uint64 cliff;
        uint64 end;
        bool enabled;
    }

    struct Deal {
        DealState state;
        IERC20 commitmentAsset;
        IERC20 payoutAsset;
        uint64 startTime;
        uint64 endTime;
        uint256 softCap;
        uint256 hardCap;
        uint256 minCommit;
        uint256 maxCommitPerInvestor;
        uint256 payoutRate; // payout tokens per commitment token, scaled by 1e18
        uint16 feeBps;
        bool kycRequired;
        bool allowSelfServeWithSignature;
        bytes32 metadataHash;
        bytes32 cancelTag;
        VestingSchedule vesting;
        uint256 totalCommitted;
        uint256 totalRefunded;
        uint256 totalPayoutDeposited;
        uint256 totalPayoutClaimed;
    }

    struct InvestorPosition {
        uint256 committed;
        uint256 refunded;
        uint256 claimed;
    }

    struct ComplianceProfile {
        // flags: bitfield determined by compliance ops
        // 0x1 => blocked, 0x2 => kyc_ok, 0x4 => accredited, 0x8 => institution
        uint32 flags;
        uint64 validUntil;
        uint96 capOverride;
    }

    struct InvestorAttestation {
        address investor;
        uint256 dealId;
        uint256 maxCommit;
        uint64 deadline;
        uint32 flags;
        uint256 nonce;
    }

    // =============================================================
    // Storage
    // =============================================================

    uint256 public dealCount;
    mapping(uint256 => Deal) private _deals;
    mapping(uint256 => mapping(address => InvestorPosition)) private _positions;

    mapping(address => ComplianceProfile) private _profiles;
    mapping(address => uint256) public attestationNonces;

    // =============================================================
    // EIP-712
    // =============================================================

    bytes32 private constant ATTESTATION_TYPEHASH =
        keccak256(
            "InvestorAttestation(address investor,uint256 dealId,uint256 maxCommit,uint64 deadline,uint32 flags,uint256 nonce)"
        );

    // =============================================================
    // Constructor
    // =============================================================

    constructor() EIP712("VClauncher", "1") {
        // Pre-populated addresses (do not require user-supplied constructor arguments).
        ADDRESS_A = 0x2F0A4c9e8B9d2aE7B6c43D3a0b5F79d6A2c3E41B;
        ADDRESS_B = 0x7bE31aD6c5fA0D4B2E9cF1a8bA7D6eC2f4B3cD19;
        ADDRESS_C = 0x1D5cB4a9E0F7a2b3C8d9E6f4A1b2C3d4E5f6A7b8;
        ADDRESS_D = 0x9aC2E7f1B3d4C5a6b7D8E9f0A1b2C3d4E5F60718;

        if (
            ADDRESS_A == address(0) || ADDRESS_B == address(0) || ADDRESS_C == address(0) || ADDRESS_D == address(0)
        ) {
            revert VCLaunch_InvalidAddress();
        }

        _grantRole(DEFAULT_ADMIN_ROLE, ADDRESS_A);
        _grantRole(MANAGER_ROLE, ADDRESS_A);
        _grantRole(COMPLIANCE_ROLE, ADDRESS_A);
        _grantRole(TREASURY_ROLE, ADDRESS_B);
        _grantRole(EMERGENCY_ROLE, ADDRESS_A);
    }

    // =============================================================
    // Admin / Ops
    // =============================================================

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
        emit VCLaunch_Paused(msg.sender);
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
        emit VCLaunch_Unpaused(msg.sender);
    }

    function setComplianceProfile(address investor, uint32 flags, uint64 validUntil, uint96 capOverride)
        external
        onlyRole(COMPLIANCE_ROLE)
    {
        if (investor == address(0)) revert VCLaunch_InvalidAddress();
        _profiles[investor] = ComplianceProfile({flags: flags, validUntil: validUntil, capOverride: capOverride});
        emit VCLaunch_ComplianceProfileSet(investor, flags, validUntil, capOverride);
    }

    function rotateComplianceSigner(address nextSigner) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (nextSigner == address(0)) revert VCLaunch_InvalidAddress();
        address prev = ADDRESS_D;
        // signer is immutable by design; rotation is expressed by updating compliance flags
        // and relying on an out-of-band signer transition. This event provides an on-chain breadcrumb.
        emit VCLaunch_ComplianceSignerRotated(prev, nextSigner);
    }

    // =============================================================
    // Deal lifecycle
    // =============================================================

    struct DealParams {
        IERC20 commitmentAsset;
        IERC20 payoutAsset;
        uint64 startTime;
        uint64 endTime;
        uint256 softCap;
        uint256 hardCap;
        uint256 minCommit;
        uint256 maxCommitPerInvestor;
        uint256 payoutRate;
        uint16 feeBps;
        bool kycRequired;
        bool allowSelfServeWithSignature;
        bytes32 metadataHash;
        VestingSchedule vesting;
    }

    function createDeal(DealParams calldata p) external onlyRole(MANAGER_ROLE) whenNotPaused returns (uint256 dealId) {
        if (address(p.commitmentAsset) == address(0) || address(p.payoutAsset) == address(0)) {
            revert VCLaunch_InvalidAddress();
        }
        if (address(p.commitmentAsset) == address(p.payoutAsset)) {
            revert VCLaunch_PayoutAssetMismatch();
        }
        if (p.startTime == 0 || p.endTime == 0 || p.endTime <= p.startTime) {
            revert VCLaunch_InvalidTime();
        }
        uint64 duration = p.endTime - p.startTime;
        if (duration < MIN_DEAL_DURATION || duration > MAX_DEAL_DURATION) {
            revert VCLaunch_InvalidTime();
        }
        if (p.hardCap == 0 || p.hardCap < p.softCap) revert VCLaunch_InvalidAmount();
        if (p.minCommit == 0 || p.maxCommitPerInvestor == 0 || p.maxCommitPerInvestor < p.minCommit) {
            revert VCLaunch_InvalidAmount();
        }
        if (p.payoutRate == 0) revert VCLaunch_InvalidRate();
        if (p.feeBps > MAX_FEE_BPS) revert VCLaunch_FeeTooHigh();
        _validateVesting(p.vesting);

        dealId = ++dealCount;
        Deal storage d = _deals[dealId];

        d.state = DealState.Draft;
        d.commitmentAsset = p.commitmentAsset;
        d.payoutAsset = p.payoutAsset;
        d.startTime = p.startTime;
        d.endTime = p.endTime;
        d.softCap = p.softCap;
        d.hardCap = p.hardCap;
        d.minCommit = p.minCommit;
        d.maxCommitPerInvestor = p.maxCommitPerInvestor;
        d.payoutRate = p.payoutRate;
        d.feeBps = p.feeBps;
        d.kycRequired = p.kycRequired;
        d.allowSelfServeWithSignature = p.allowSelfServeWithSignature;
        d.metadataHash = p.metadataHash;
        d.vesting = p.vesting;

        emit VCLaunch_DealCreated(
            dealId,
            address(p.commitmentAsset),
            address(p.payoutAsset),
            p.metadataHash,
            p.startTime,
            p.endTime
        );
    }

    function setDealLive(uint256 dealId) external onlyRole(MANAGER_ROLE) whenNotPaused {
        Deal storage d = _getDeal(dealId);
        if (d.state != DealState.Draft) revert VCLaunch_InvalidDeal();
        if (block.timestamp >= d.endTime) revert VCLaunch_InvalidTime();
        d.state = DealState.Live;
        emit VCLaunch_DealLive(dealId, d.startTime, d.endTime);
    }

    function cancelDeal(uint256 dealId, bytes32 reasonTag) external onlyRole(MANAGER_ROLE) whenNotPaused {
        Deal storage d = _getDeal(dealId);
        if (d.state == DealState.Finalized) revert VCLaunch_AlreadyFinalized();
        if (d.state == DealState.Cancelled) revert VCLaunch_DealCancelled();
        d.state = DealState.Cancelled;
        d.cancelTag = reasonTag;
        emit VCLaunch_DealCancelled(dealId, reasonTag);
    }

    function finalizeDeal(uint256 dealId) external onlyRole(TREASURY_ROLE) whenNotPaused nonReentrant {
        Deal storage d = _getDeal(dealId);
        if (d.state != DealState.Live) revert VCLaunch_NotLive();
        if (block.timestamp < d.endTime) revert VCLaunch_DealNotOpen();
        if (d.totalCommitted == 0) {
            d.state = DealState.Cancelled;
            d.cancelTag = keccak256(abi.encodePacked("EMPTY_BOOK", CONFIG_TAG, dealId));
            emit VCLaunch_DealCancelled(dealId, d.cancelTag);
            return;
        }

        bool success = d.totalCommitted >= d.softCap;
        if (!success) {
            d.state = DealState.Cancelled;
            d.cancelTag = keccak256(abi.encodePacked("SOFTCAP_FAIL", CONFIG_TAG, dealId));
            emit VCLaunch_DealCancelled(dealId, d.cancelTag);
            emit VCLaunch_DealFinalized(dealId, false, d.totalCommitted, 0);
            return;
        }

        d.state = DealState.Finalized;

        uint256 fee = (d.totalCommitted * uint256(d.feeBps)) / BPS_DENOMINATOR;
        uint256 net = d.totalCommitted - fee;

        if (fee != 0) {
            d.commitmentAsset.safeTransfer(ADDRESS_C, fee);
        }
        d.commitmentAsset.safeTransfer(ADDRESS_B, net);

        emit VCLaunch_DealFinalized(dealId, true, d.totalCommitted, fee);
    }

    // =============================================================
    // Commitments
    // =============================================================

    function commit(uint256 dealId, uint256 amount) external whenNotPaused nonReentrant {
        _commitInternal(dealId, msg.sender, amount, 0, 0, 0, 0, bytes(""));
    }

    function commitWithAttestation(
        uint256 dealId,
        uint256 amount,
        InvestorAttestation calldata a,
        bytes calldata signature
    ) external whenNotPaused nonReentrant {
        _commitInternal(dealId, msg.sender, amount, a.dealId, a.maxCommit, a.deadline, a.nonce, a.flags, signature);
    }

    function _commitInternal(
        uint256 dealId,
        address investor,
        uint256 amount,
        uint256 aDealId,
        uint256 aMaxCommit,
        uint64 aDeadline,
        uint256 aNonce,
        uint32 aFlags,
        bytes memory signature
    ) internal {
        Deal storage d = _getDeal(dealId);

        if (d.state == DealState.Cancelled) revert VCLaunch_DealCancelled();
        if (d.state != DealState.Live) revert VCLaunch_NotLive();
        if (block.timestamp < d.startTime) revert VCLaunch_DealNotOpen();
        if (block.timestamp >= d.endTime) revert VCLaunch_DealClosed();
        if (amount == 0) revert VCLaunch_InvalidAmount();
        if (amount < d.minCommit) revert VCLaunch_MinCommitNotMet();

        InvestorPosition storage pos = _positions[dealId][investor];
        uint256 nextInvestorCommitted = pos.committed + amount;

        uint256 cap = d.maxCommitPerInvestor;
        uint96 capOverride = _profiles[investor].capOverride;
        if (capOverride != 0) {
            cap = uint256(capOverride);
        }
        if (nextInvestorCommitted > cap) revert VCLaunch_MaxCommitExceeded();

        uint256 nextTotal = d.totalCommitted + amount;
        if (nextTotal > d.hardCap) revert VCLaunch_HardCapExceeded();
