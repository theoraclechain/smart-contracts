// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

//
// ----------------- OpenZeppelin-like Minimal Contracts (Flattened) -----------------
//

/**
 * @title Context
 * @dev Provides information about the current execution context, including the sender of the transaction.
 */
abstract contract Context {
    /**
     * @notice Returns the address of the current transaction sender.
     * @return The address of the sender.
     */
    function _msgSender() internal view virtual returns (address) { return msg.sender; }
}

/**
 * @title IERC165
 * @dev Interface for the ERC165 standard, allowing contracts to declare support for interfaces.
 */
interface IERC165 {
    /**
     * @notice Queries if a contract implements an interface.
     * @param interfaceId The interface identifier, as specified in ERC-165.
     * @return `true` if the contract implements `interfaceId`, `false` otherwise.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/**
 * @title ERC165
 * @dev Implementation of the IERC165 interface for interface detection.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @notice Checks if the contract supports a given interface.
     * @dev Overrides IERC165's supportsInterface to check for IERC165 itself.
     * @param interfaceId The interface identifier to check.
     * @return `true` if the interface is supported, `false` otherwise.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

/**
 * @title Strings
 * @dev Library for converting uint256 and address values to hexadecimal strings.
 */
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";

    /**
     * @notice Converts a uint256 to its hexadecimal string representation with a specified length.
     * @param value The uint256 value to convert.
     * @param length The desired length of the hexadecimal string (excluding "0x").
     * @return The hexadecimal string representation.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        return string(buffer);
    }

    /**
     * @notice Converts an address to its hexadecimal string representation.
     * @param value The address to convert.
     * @return The hexadecimal string representation.
     */
    function toHexString(address value) internal pure returns (string memory) {
        return toHexString(uint256(uint160(value)), 20);
    }
}

/**
 * @title IAccessControl
 * @dev Interface for role-based access control, allowing management of roles and permissions.
 */
interface IAccessControl is IERC165 {
    /**
     * @notice Emitted when the admin role for a role is changed.
     * @param role The role whose admin is changed.
     * @param previousAdminRole The previous admin role.
     * @param newAdminRole The new admin role.
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @notice Emitted when a role is granted to an account.
     * @param role The role granted.
     * @param account The account receiving the role.
     * @param sender The account that granted the role.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @notice Emitted when a role is revoked from an account.
     * @param role The role revoked.
     * @param account The account losing the role.
     * @param sender The account that revoked the role.
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @notice Checks if an account has a specific role.
     * @param role The role to check.
     * @param account The account to verify.
     * @return `true` if the account has the role, `false` otherwise.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @notice Returns the admin role for a given role.
     * @param role The role to query.
     * @return The admin role identifier.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @notice Grants a role to an account.
     * @param role The role to grant.
     * @param account The account to receive the role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @notice Revokes a role from an account.
     * @param role The role to revoke.
     * @param account The account to lose the role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @notice Allows an account to renounce a role it holds.
     * @param role The role to renounce.
     * @param account The account renouncing the role.
     */
    function renounceRole(bytes32 role, address account) external;
}

/**
 * @title AccessControl
 * @dev Implements role-based access control with admin roles and permission management.
 */
abstract contract AccessControl is Context, ERC165, IAccessControl {
    /**
     * @dev Struct to store role membership and admin role data.
     * @param members Mapping of addresses to their role membership status.
     * @param adminRole The role that administers this role.
     */
    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    /// @notice Mapping of roles to their data (members and admin role).
    mapping(bytes32 => RoleData) private _roles;

    /// @notice The default admin role identifier (0x00).
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @notice Checks if the contract supports a given interface.
     * @dev Overrides ERC165 to include IAccessControl interface support.
     * @param interfaceId The interface identifier to check.
     * @return `true` if the interface is supported, `false` otherwise.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC165) returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @notice Checks if an account has a specific role.
     * @param role The role to check.
     * @param account The account to verify.
     * @return `true` if the account has the role, `false` otherwise.
     */
    function hasRole(bytes32 role, address account) public view virtual override returns (bool) {
        return _roles[role].members[account];
    }

    /**
     * @notice Returns the admin role for a given role.
     * @param role The role to query.
     * @return The admin role identifier.
     */
    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) {
        bytes32 admin = _roles[role].adminRole;
        return admin == bytes32(0) ? DEFAULT_ADMIN_ROLE : admin;
    }

    /**
     * @dev Internal function to check if an account has a role, reverting if not.
     * @param role The role to check.
     * @param account The account to verify.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert(string(abi.encodePacked("AccessControl: account ", Strings.toHexString(account), " is missing role ", Strings.toHexString(uint256(role), 32))));
        }
    }

    /**
     * @dev Internal function to grant a role to an account.
     * @param role The role to grant.
     * @param account The account to receive the role.
     */
    function _grantRole(bytes32 role, address account) internal virtual {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }

    /**
     * @dev Internal function to revoke a role from an account.
     * @param role The role to revoke.
     * @param account The account to lose the role.
     */
    function _revokeRole(bytes32 role, address account) internal virtual {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }

    /**
     * @notice Grants a role to an account.
     * @dev Only callable by the admin of the role.
     * @param role The role to grant.
     * @param account The account to receive the role.
     */
    function grantRole(bytes32 role, address account) external virtual override {
        _checkRole(getRoleAdmin(role), _msgSender());
        _grantRole(role, account);
    }

    /**
     * @notice Revokes a role from an account.
     * @dev Only callable by the admin of the role.
     * @param role The role to revoke.
     * @param account The account to lose the role.
     */
    function revokeRole(bytes32 role, address account) external virtual override {
        _checkRole(getRoleAdmin(role), _msgSender());
        _revokeRole(role, account);
    }

    /**
     * @notice Allows an account to renounce a role it holds.
     * @dev Can only be called by the account itself.
     * @param role The role to renounce.
     * @param account The account renouncing the role.
     */
    function renounceRole(bytes32 role, address account) external virtual override {
        require(account == _msgSender(), "AccessControl: can only renounce for self");
        _revokeRole(role, account);
    }
}

/**
 * @title IERC20
 * @dev Interface for the ERC20 token standard.
 */
interface IERC20 {
    /**
     * @notice Emitted when tokens are transferred from one address to another.
     * @param from The source address.
     * @param to The destination address.
     * @param value The amount of tokens transferred.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @notice Emitted when an approval is set for a spender.
     * @param owner The owner of the tokens.
     * @param spender The address allowed to spend tokens.
     * @param value The amount of tokens approved.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice Returns the total supply of the token.
     * @return The total supply.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @notice Returns the balance of an account.
     * @param account The account to query.
     * @return The balance of the account.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @notice Transfers tokens to a recipient.
     * @param to The recipient address.
     * @param value The amount to transfer.
     * @return `true` if the transfer succeeds, `false` otherwise.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @notice Returns the amount a spender is allowed to spend on behalf of an owner.
     * @param owner The owner of the tokens.
     * @param spender The address allowed to spend.
     * @return The remaining allowance.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @notice Approves a spender to spend tokens on behalf of the caller.
     * @param spender The address to approve.
     * @param value The amount to approve.
     * @return `true` if the approval succeeds, `false` otherwise.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @notice Transfers tokens from one address to another using an allowance.
     * @param from The source address.
     * @param to The destination address.
     * @param value The amount to transfer.
     * @return `true` if the transfer succeeds, `false` otherwise.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

//
// ----------------- End of OpenZeppelin-like Contracts -----------------
//

/**
 * @title OffersData
 * @author The Oracle Chain Team
 * @notice Storage contract for all offers and their related financial statistics in The Oracle Chain.
 * @dev Acts as a secure on-chain database, modifiable only by an authorized OffersLogic contract.
 *      Separates data from business logic for enhanced security and upgradeability.
 *      Integrates with PythiaToken for $PYTHIA transactions and OracleRevelation for draw validation.
 */
contract OffersData is AccessControl {
    // ──────────────────────── STATE ────────────────────────

    /// @notice The address of the OffersLogic contract authorized to modify data.
    address public logicContract;

    /// @notice The address of the ERC20 token used for offers and prizes (immutable).
    IERC20 public immutable token;

    /**
     * @notice Struct containing the data for a single offer.
     * @param amount The gross amount wagered by the user in $PYTHIA.
     * @param netAmount The net amount after fee (5%) and burn (1% or 100%) deductions, contributing to the prize pool.
     * @param icons The array of 2-5 symbols (1-90) chosen by the user.
     * @param claimed Flag indicating if the prize for this offer has been claimed.
     * @param refunded Flag indicating if the offer has been refunded (e.g., for a cancelled draw).
     */
    struct Offer {
        uint256 amount;
        uint256 netAmount;
        uint8[] icons;
        bool claimed;
        bool refunded;
    }

    /// @notice Main storage for offers: maps drawId => user => offerIndex => Offer data.
    mapping(uint256 => mapping(address => mapping(uint256 => Offer))) public offers;

    /// @notice Counter for the number of offers per user in each draw.
    mapping(uint256 => mapping(address => uint256)) public offerCount;

    /// @notice The net prize pool (contributions net of fees/burn) for each draw.
    mapping(uint256 => uint256) public prizePool;

    /// @notice The total gross volume wagered for each draw in $PYTHIA.
    mapping(uint256 => uint256) public totalVolumeByDraw;

    /// @notice The all-time gross volume wagered since the contract's inception in $PYTHIA.
    uint256 public totalLifetimeVolume;

    /// @notice Admin-configurable flag: if true, prize claims decrement the prizePool.
    bool public decrementPrizePoolOnClaim;

    // ──────────────────────── EVENTS ────────────────────────

    /**
     * @notice Emitted when the authorized OffersLogic contract address is updated.
     * @param logicContractAddress The new OffersLogic contract address.
     * @param changedBy The admin address that made the change.
     */
    event LogicContractSet(address indexed logicContractAddress, address indexed changedBy);

    /**
     * @notice Emitted when a new offer is recorded.
     * @param drawId The ID of the draw.
     * @param user The address of the user placing the offer.
     * @param offerIndex The index of the offer for the user in the draw.
     * @param amount The gross amount wagered in $PYTHIA.
     * @param netAmount The net amount after deductions in $PYTHIA.
     * @param icons The array of symbols chosen (1-90).
     */
    event NewOffer(uint256 indexed drawId, address indexed user, uint256 indexed offerIndex, uint256 amount, uint256 netAmount, uint8[] icons);

    /**
     * @notice Emitted when a prize is claimed for an offer.
     * @param drawId The ID of the draw.
     * @param user The address of the user claiming the prize.
     * @param offerIndex The index of the offer.
     * @param netAmountDeducted The amount deducted from the prize pool (if decrementPrizePoolOnClaim is true).
     */
    event PrizeClaimedData(uint256 indexed drawId, address indexed user, uint256 indexed offerIndex, uint256 netAmountDeducted);

    /**
     * @notice Emitted when an offer is refunded due to a cancelled draw.
     * @param drawId The ID of the draw.
     * @param user The address of the user receiving the refund.
     * @param offerIndex The index of the offer.
     */
    event OfferRefundedData(uint256 indexed drawId, address indexed user, uint256 indexed offerIndex);

    /**
     * @notice Emitted when the decrementPrizePoolOnClaim flag is updated.
     * @param oldValue The previous value of the flag.
     * @param newValue The new value of the flag.
     */
    event DecrementPrizePoolOnClaimUpdated(bool oldValue, bool newValue);

    // ──────────────────────── MODIFIERS ────────────────────────

    /**
     * @dev Restricts function access to accounts with the specified role.
     * @param role The role to check.
     */
    modifier onlyRole(bytes32 role) { _checkRole(role, _msgSender()); _; }

    /**
     * @dev Restricts function access to the authorized OffersLogic contract.
     */
    modifier onlyLogicContract() { require(msg.sender == logicContract, "OffersData: not logic contract"); _; }

    // ─────────────────────── CONSTRUCTOR ─────────────────────

    /**
     * @notice Initializes the contract with the admin and token address.
     * @dev Sets the DEFAULT_ADMIN_ROLE and initializes the ERC20 token address for $PYTHIA.
     *      The decrementPrizePoolOnClaim flag is set to false by default.
     * @param admin The address to receive the DEFAULT_ADMIN_ROLE.
     * @param tokenAddress The address of the $PYTHIA ERC20 token contract.
     */
    constructor(address admin, address tokenAddress) {
        require(admin != address(0) && tokenAddress != address(0), "OffersData: zero address");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        token = IERC20(tokenAddress);
        decrementPrizePoolOnClaim = false; // By default, prize pool is an additive counter only.
    }

    // ─────────────────────── ADMIN FUNCTIONS ───────────────────

    /**
     * @notice Sets or updates the address of the authorized OffersLogic contract.
     * @dev Only callable by the DEFAULT_ADMIN_ROLE. Emits a LogicContractSet event.
     * @param _logic The address of the new OffersLogic contract.
     */
    function setLogicContract(address _logic) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_logic != address(0), "OffersData: logic address is zero");
        logicContract = _logic;
        emit LogicContractSet(_logic, _msgSender());
    }

    /**
     * @notice Enables or disables decrementing the prizePool upon prize claims.
     * @dev Only callable by the DEFAULT_ADMIN_ROLE. If enabled, prizePool tracks available balance;
     *      if disabled, it tracks total collected amount. Emits a DecrementPrizePoolOnClaimUpdated event.
     * @param enabled The new state of the flag.
     */
    function setDecrementPrizePoolOnClaim(bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit DecrementPrizePoolOnClaimUpdated(decrementPrizePoolOnClaim, enabled);
        decrementPrizePoolOnClaim = enabled;
    }

    // ───────────────── WRITE FUNCTIONS (API for OffersLogic) ─────────────────

    /**
     * @notice Records a new offer and updates financial metrics.
     * @dev Only callable by the OffersLogic contract. Updates prizePool, totalVolumeByDraw,
     *      totalLifetimeVolume, and offerCount. Emits a NewOffer event.
     * @param drawId The ID of the draw.
     * @param user The address of the user placing the offer.
     * @param amount The gross amount wagered in $PYTHIA.
     * @param netAmount The net amount after fee and burn deductions in $PYTHIA.
     * @param icons The array of 2-5 symbols (1-90) chosen by the user.
     * @return offerIndex The index of the new offer for the user in the draw.
     */
    function processNewOffer(uint256 drawId, address user, uint256 amount, uint256 netAmount, uint8[] calldata icons)
        external onlyLogicContract returns (uint256 offerIndex)
    {
        offerIndex = offerCount[drawId][user];
        offers[drawId][user][offerIndex] = Offer({ amount: amount, netAmount: netAmount, icons: icons, claimed: false, refunded: false });
        offerCount[drawId][user]++;

        prizePool[drawId] += netAmount;
        totalVolumeByDraw[drawId] += amount;
        totalLifetimeVolume += amount;

        emit NewOffer(drawId, user, offerIndex, amount, netAmount, icons);
        return offerIndex;
    }

    /**
     * @notice Processes a prize claim for an offer.
     * @dev Only callable by the OffersLogic contract. Marks the offer as claimed and optionally
     *      decrements the prizePool if decrementPrizePoolOnClaim is true. Emits a PrizeClaimedData event.
     * @param drawId The ID of the draw.
     * @param user The address of the user claiming the prize.
     * @param offerIndex The index of the offer.
     */
    function processPrizeClaim(uint256 drawId, address user, uint256 offerIndex) external onlyLogicContract {
        Offer storage offer = offers[drawId][user][offerIndex];
        require(!offer.claimed, "OffersData: already claimed");
        offer.claimed = true;

        uint256 deducted = 0;
        if (decrementPrizePoolOnClaim) {
            uint256 net = offer.netAmount;
            // This check prevents underflow if the economic model changes.
            if (prizePool[drawId] >= net) {
                prizePool[drawId] -= net;
                deducted = net;
            }
        }
        emit PrizeClaimedData(drawId, user, offerIndex, deducted);
    }

    /**
     * @notice Processes a refund for an offer in a cancelled draw.
     * @dev Only callable by the OffersLogic contract. Marks the offer as refunded.
     *      Emits an OfferRefundedData event.
     * @param drawId The ID of the draw.
     * @param user The address of the user receiving the refund.
     * @param offerIndex The index of the offer.
     */
    function processRefund(uint256 drawId, address user, uint256 offerIndex) external onlyLogicContract {
        Offer storage offer = offers[drawId][user][offerIndex];
        require(!offer.refunded, "OffersData: already refunded");
        offer.refunded = true;
        emit OfferRefundedData(drawId, user, offerIndex);
    }

    // ──────────────────────── VIEW FUNCTIONS ───────────────────

    /**
     * @notice Returns the main data for a single offer.
     * @param drawId The ID of the draw.
     * @param user The address of the user who placed the offer.
     * @param offerIndex The index of the offer.
     * @return amount The gross amount wagered in $PYTHIA.
     * @return icons The array of symbols chosen (1-90).
     * @return claimed Whether the prize has been claimed.
     * @return refunded Whether the offer has been refunded.
     */
    function getOffer(uint256 drawId, address user, uint256 offerIndex)
        external view returns (uint256 amount, uint8[] memory icons, bool claimed, bool refunded)
    {
        Offer storage o = offers[drawId][user][offerIndex];
        return (o.amount, o.icons, o.claimed, o.refunded);
    }

    /**
     * @notice Returns the net amount of a specific offer.
     * @param drawId The ID of the draw.
     * @param user The address of the user who placed the offer.
     * @param offerIndex The index of the offer.
     * @return The net amount after fee and burn deductions in $PYTHIA.
     */
    function getOfferNetAmount(uint256 drawId, address user, uint256 offerIndex) external view returns (uint256) {
        return offers[drawId][user][offerIndex].netAmount;
    }

    /**
     * @notice Returns the number of offers a user has placed for a specific draw.
     * @param drawId The ID of the draw.
     * @param user The address of the user.
     * @return The number of offers placed.
     */
    function getOfferCount(uint256 drawId, address user) external view returns (uint256) {
        return offerCount[drawId][user];
    }
}
