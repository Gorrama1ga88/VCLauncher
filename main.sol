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
