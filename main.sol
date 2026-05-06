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
