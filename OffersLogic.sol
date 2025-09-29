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
    function _msgSender() internal view virtual returns (address) { return msg.sender; }
}

/**
 * @title IERC165
 * @dev Interface for the ERC165 standard, allowing contracts to declare support for interfaces.
 */
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/**
 * @title ERC165
 * @dev Implementation of the IERC165 interface for interface detection.
 */
abstract contract ERC165 is IERC165 {
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
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2); buffer[0] = "0"; buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) { buffer[i] = _SYMBOLS[value & 0xf]; value >>= 4; }
        return string(buffer);
    }
    function toHexString(address value) internal pure returns (string memory) { return toHexString(uint256(uint160(value)), 20); }
}

/**
 * @title IAccessControl
 * @dev Interface for role-based access control, allowing management of roles and permissions.
 */
interface IAccessControl is IERC165 {
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    function hasRole(bytes32 role, address account) external view returns (bool);
    function getRoleAdmin(bytes32 role) external view returns (bytes32);
    function grantRole(bytes32 role, address account) external;
    function revokeRole(bytes32 role, address account) external;
    function renounceRole(bytes32 role, address account) external;
}

/**
 * @title AccessControl
 * @dev Implements role-based access control with admin roles and permission management.
 */
abstract contract AccessControl is Context, ERC165, IAccessControl {
    struct RoleData { mapping(address => bool) members; bytes32 adminRole; }
    mapping(bytes32 => RoleData) private _roles;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC165) returns (bool) { return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId); }
    function hasRole(bytes32 role, address account) public view virtual override returns (bool) { return _roles[role].members[account]; }
    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) { bytes32 admin = _roles[role].adminRole; return admin == bytes32(0) ? DEFAULT_ADMIN_ROLE : admin; }
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual { bytes32 previous = _roles[role].adminRole; _roles[role].adminRole = adminRole; emit RoleAdminChanged(role, previous, adminRole); }
    function _checkRole(bytes32 role, address account) internal view virtual { if (!hasRole(role, account)) { revert(string(abi.encodePacked("AccessControl: account ", Strings.toHexString(account), " is missing role ", Strings.toHexString(uint256(role), 32)))); } }
    function _grantRole(bytes32 role, address account) internal virtual { if (!hasRole(role, account)) { _roles[role].members[account] = true; emit RoleGranted(role, account, _msgSender()); } }
    function _revokeRole(bytes32 role, address account) internal virtual { if (hasRole(role, account)) { _roles[role].members[account] = false; emit RoleRevoked(role, account, _msgSender()); } }
    function grantRole(bytes32 role, address account) external virtual override { _checkRole(getRoleAdmin(role), _msgSender()); _grantRole(role, account); }
    function revokeRole(bytes32 role, address account) external virtual override { _checkRole(getRoleAdmin(role), _msgSender()); _revokeRole(role, account); }
    function renounceRole(bytes32 role, address account) external virtual override { require(account == _msgSender(), "AccessControl: can only renounce for self"); _revokeRole(role, account); }
}

/**
 * @title ReentrancyGuard
 * @dev Prevents reentrant calls to critical functions to avoid vulnerabilities.
 */
abstract contract ReentrancyGuard {
    uint256 private _status;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    constructor() { _status = _NOT_ENTERED; }
    modifier nonReentrant() { require(_status != _ENTERED, "ReentrancyGuard: reentrant"); _status = _ENTERED; _; _status = _NOT_ENTERED; }
}

/**
 * @title IERC20
 * @dev Interface for the ERC20 token standard.
 */
interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/**
 * @title IOracleRevelation
 * @dev Interface for interacting with the OracleRevelation contract to manage draws and revelations.
 */
interface IOracleRevelation {
    function currentOpenDraw() external view returns (bool exists_, uint256 drawId_, uint64 deadline_);
    function getClaimParameters(uint256 drawId) external view returns (bool revealed_, uint64 publishedAt_, uint8[5] memory icons_, bool cancelled_);
    function isCancelled(uint256 drawId) external view returns (bool);
    function getLastPublished() external view returns (uint256);
    function nextPlayableDrawId() external view returns (uint256);
}

/**
 * @title IOffersData
 * @dev Interface for interacting with the OffersData contract to manage offer storage.
 */
interface IOffersData {
    function token() external view returns (IERC20);
    function getOffer(uint256 drawId, address user, uint256 offerIndex) external view returns (uint256 amount, uint8[] memory icons, bool claimed, bool refunded);
    function processNewOffer(uint256 drawId, address user, uint256 amount, uint256 netAmount, uint8[] calldata icons) external returns (uint256 offerIndex);
    function processPrizeClaim(uint256 drawId, address user, uint256 offerIndex) external;
    function processRefund(uint256 drawId, address user, uint256 offerIndex) external;
}

/**
 * @title OffersLogic
 * @author The Oracle Chain Team
 * @notice Manages logic for offers, now with an optional charity donation feature.
 * @dev Handles validation, prize calculation, and token routing for $PYTHIA. Users can
 *      choose to burn 1% of their offer (2-4 symbols) or donate it to a charity.
 */
contract OffersLogic is AccessControl, ReentrancyGuard {
    // --- EVENTS ---
    event OfferPlaced(address indexed user, uint256 indexed drawId, uint256 offerIndex, uint256 amount, uint8[] icons);
    event PrizeClaimed(address indexed user, uint256 indexed drawId, uint256 offerIndex, uint256 prizeAmount);
    event OfferRefunded(address indexed user, uint256 indexed drawId, uint256 offerIndex, uint256 refundAmount);
    event FeeWalletUpdated(address indexed oldWallet, address indexed newWallet);
    event FeeBpsUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event OfferAmountsUpdated(uint256 oldMin, uint256 oldMax, uint256 newMin, uint256 newMax);
    event IconCountLimitsUpdated(uint8 iconCount, uint256 oldMin, uint256 oldMax, uint256 newMin, uint256 newMax);
    event PausedSet(bool oldPaused, bool newPaused);
    event BurnParamsUpdated(address indexed oldBurnWallet, address indexed newBurnWallet, uint256 oldBurnBpsOther, uint256 newBurnBpsOther);
    event TokensBurned(address indexed user, uint256 indexed drawId, uint8 iconCount, uint256 amount);

    
    /**
     * @notice Emitted when the charity wallet address is updated.
     * @param oldWallet The previous charity wallet address.
     * @param newWallet The new charity wallet address.
     */
    event CharityWalletUpdated(address indexed oldWallet, address indexed newWallet);
    /**
     * @notice Emitted when a user chooses to donate a portion of their offer.
     * @param user The address of the user making the donation.
     * @param drawId The ID of the draw.
     * @param amount The amount of $PYTHIA donated.
     */
    event DonationMade(address indexed user, uint256 indexed drawId, uint256 amount);
    

    // --- ERRORS ---
    error DrawNotOpen(); error AmountOutOfBounds(); error InvalidIconCount(); error IconOutOfRange();
    error DuplicateIcon(); error NoOfferFound(); error PrizeAlreadyClaimed(); error OfferAlreadyRefunded();
    error DrawNotRevealed(); error ClaimWindowClosed(); error NoPrizeToClaim(); error DrawCancelled();
    error InsufficientContractBalance(); error Paused();

    // --- STATE VARIABLES ---
    IOracleRevelation public immutable revelation;
    IOffersData public immutable offersData;
    IERC20 public immutable token;
    address public feeWallet;
    bool public paused;
    uint256 public minOfferAmount;
    uint256 public maxOfferAmount;
    mapping(uint8 => uint256) public minByIconCount;
    mapping(uint8 => uint256) public maxByIconCount;
    uint256 public feeBps;
    address public burnWallet;
    uint256 public burnBpsOther;
    
    
    /// @notice The address where charity donations (1%) are sent.
    address public charityWallet;
    /// @notice The role for managing the charity wallet address.
    bytes32 public constant CHARITY_ADMIN_ROLE = keccak256("CHARITY_ADMIN_ROLE");
   

    // --- CONSTANTS ---
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant CLAIM_WINDOW = 7 days;
    uint256 public constant MULT_2 = 250;
    uint256 public constant MULT_3 = 4_250;
    uint256 public constant MULT_4 = 80_000;
    uint256 public constant MULT_5 = 1_000_000;

    modifier onlyRole(bytes32 role) { _checkRole(role, _msgSender()); _; }

    /**
     * @notice Initializes the contract with all required addresses.
     * @dev Sets roles, immutable contracts, and default parameters, including the initial charity wallet.
     * @param admin The address for the DEFAULT_ADMIN_ROLE.
     * @param _revelationAddr The address of the OracleRevelation contract.
     * @param _offersDataAddr The address of the OffersData contract.
     * @param _feeWallet The address to receive fees.
     * @param _initialCharityWallet The initial address for charity donations.
     */
    constructor(
        address admin,
        address _revelationAddr,
        address _offersDataAddr,
        address _feeWallet,
        address _initialCharityWallet 
    ) {
        require(admin != address(0) && _revelationAddr != address(0) && _offersDataAddr != address(0) && _feeWallet != address(0), "OffersLogic: zero address");
        require(_initialCharityWallet != address(0), "OffersLogic: zero charity address"); 
        
        _setRoleAdmin(DEFAULT_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);

        _setRoleAdmin(CHARITY_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _grantRole(CHARITY_ADMIN_ROLE, admin);
        charityWallet = _initialCharityWallet;

        revelation = IOracleRevelation(_revelationAddr);
        offersData = IOffersData(_offersDataAddr);
        token = offersData.token();
        feeWallet = _feeWallet;

        minOfferAmount = 100 * 1e18;  maxOfferAmount = 10_000 * 1e18;
        minByIconCount[2] = 100 * 1e18;  maxByIconCount[2] = 10_000 * 1e18;
        minByIconCount[3] = 100 * 1e18;  maxByIconCount[3] = 10_000 * 1e18;
        minByIconCount[4] = 100 * 1e18;  maxByIconCount[4] = 1_000 * 1e18;
        minByIconCount[5] = 10 * 1e18;   maxByIconCount[5] = 10 * 1e18;

        feeBps = 500;
        burnWallet = 0x000000000000000000000000000000000000dEaD;
        burnBpsOther = 100;
    }

    // -------- USER --------

    /**
     * @notice Allows a user to place an offer and choose to donate a portion to charity.
     * @param icons The array of 2-5 symbols (1-90) chosen by the user.
     * @param amount The amount of $PYTHIA to wager.
     * @param sendToCharity If true, the 1% portion is sent to the charity wallet; otherwise, it is burned.
     * @return offerIndex The index of the new offer for the user in the draw.
     */
    function placeOffer(
        uint8[] calldata icons,
        uint256 amount,
        bool sendToCharity 
    ) external nonReentrant returns (uint256 offerIndex) {
        if (paused) revert Paused();
        uint256 drawId;
        { bool isOpen; uint64 deadline; (isOpen, drawId, deadline) = revelation.currentOpenDraw(); if (!isOpen || block.timestamp >= deadline) revert DrawNotOpen(); }
        { uint256 expected = revelation.nextPlayableDrawId(); require(drawId == expected, "OffersLogic: can only play on next draw"); }
        uint8 count = uint8(icons.length);
        _validateIcons(icons, count);
        { uint256 minForCount = minByIconCount[count]; uint256 maxForCount = maxByIconCount[count]; require(minForCount > 0 && maxForCount > 0, "OffersLogic: icon-count limits unset"); if (amount < minForCount || amount > maxForCount) revert AmountOutOfBounds(); }
        if (amount < minOfferAmount || amount > maxOfferAmount) revert AmountOutOfBounds();
        
        uint256 netAmount = _collectAndRoute(amount, count, drawId, sendToCharity); 
        offerIndex = _recordOffer(drawId, amount, netAmount, icons);
        emit OfferPlaced(msg.sender, drawId, offerIndex, amount, icons);
    }

    function claimPrize(uint256 drawId, uint256 offerIndex) external nonReentrant {
        (uint256 userAmount, uint8[] memory userIcons, bool isClaimed, bool isRefunded) = offersData.getOffer(drawId, msg.sender, offerIndex);
        if (userAmount == 0) revert NoOfferFound();
        if (isClaimed) revert PrizeAlreadyClaimed();
        if (isRefunded) revert OfferAlreadyRefunded();
        uint256 payout;
        { (bool isRevealed, uint64 publishedAt, uint8[5] memory winningIcons, bool isCancelled) = revelation.getClaimParameters(drawId); if (isCancelled) revert DrawCancelled(); if (!isRevealed) revert DrawNotRevealed(); if (block.timestamp > uint256(publishedAt) + CLAIM_WINDOW) revert ClaimWindowClosed(); payout = _calculatePayout(userIcons, winningIcons, userAmount); }
        if (payout == 0) revert NoPrizeToClaim();
        offersData.processPrizeClaim(drawId, msg.sender, offerIndex);
        require(token.transfer(msg.sender, payout), "OffersLogic: prize transfer failed");
        emit PrizeClaimed(msg.sender, drawId, offerIndex, payout);
    }

    function refundOffer(uint256 drawId, uint256 offerIndex) external nonReentrant {
        if (!revelation.isCancelled(drawId)) revert DrawCancelled();
        (uint256 userAmount, , bool isClaimed, bool isRefunded) = offersData.getOffer(drawId, msg.sender, offerIndex);
        if (userAmount == 0) revert NoOfferFound();
        if (isClaimed) revert PrizeAlreadyClaimed();
        if (isRefunded) revert OfferAlreadyRefunded();
        offersData.processRefund(drawId, msg.sender, offerIndex);
        require(token.transfer(msg.sender, userAmount), "OffersLogic: refund transfer failed");
        emit OfferRefunded(msg.sender, drawId, offerIndex, userAmount);
    }

    // -------- ADMIN --------

    /**
     * @notice Updates the charity wallet address.
     * @dev Only callable by an account with the CHARITY_ADMIN_ROLE. Emits a CharityWalletUpdated event.
     * @param _newWallet The new charity wallet address.
     */
    function setCharityWallet(address _newWallet) external onlyRole(CHARITY_ADMIN_ROLE) {
        require(_newWallet != address(0), "OffersLogic: zero charity");
        emit CharityWalletUpdated(charityWallet, _newWallet);
        charityWallet = _newWallet;
    }

    function setFeeWallet(address _new) external onlyRole(DEFAULT_ADMIN_ROLE) { require(_new != address(0), "OffersLogic: zero"); emit FeeWalletUpdated(feeWallet, _new); feeWallet = _new; }
    function setFeeBps(uint256 _bps) external onlyRole(DEFAULT_ADMIN_ROLE) { require(_bps < BPS_DENOMINATOR, "OffersLogic: high"); emit FeeBpsUpdated(feeBps, _bps); feeBps = _bps; }
    function setOfferAmounts(uint256 _min, uint256 _max) external onlyRole(DEFAULT_ADMIN_ROLE) { require(_min > 0 && _min < _max, "OffersLogic: invalid"); emit OfferAmountsUpdated(minOfferAmount, maxOfferAmount, _min, _max); minOfferAmount = _min; maxOfferAmount = _max; }
    function setIconCountLimits(uint8 c, uint256 minA, uint256 maxA) external onlyRole(DEFAULT_ADMIN_ROLE) { require(c >= 2 && c <= 5, "OffersLogic: c"); require(minA > 0 && minA <= maxA, "OffersLogic: min/max"); emit IconCountLimitsUpdated(c, minByIconCount[c], maxByIconCount[c], minA, maxA); minByIconCount[c] = minA; maxByIconCount[c] = maxA; }
    function setPaused(bool p) external onlyRole(DEFAULT_ADMIN_ROLE) { emit PausedSet(paused, p); paused = p; }
    function setBurnParams(address _burnWallet, uint256 _burnBpsOther) external onlyRole(DEFAULT_ADMIN_ROLE) { require(_burnWallet != address(0), "OffersLogic: zero burn"); require(_burnBpsOther <= BPS_DENOMINATOR, "OffersLogic: high burn"); emit BurnParamsUpdated(burnWallet, _burnWallet, burnBpsOther, _burnBpsOther); burnWallet = _burnWallet; burnBpsOther = _burnBpsOther; }
    function emergencyWithdrawTokens(address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) { require(to != address(0), "OffersLogic: zero"); uint256 bal = token.balanceOf(address(this)); if (amount > bal) revert InsufficientContractBalance(); require(token.transfer(to, amount), "OffersLogic: withdrawal failed"); }

    // -------- VIEW --------
    function getIconCountLimits(uint8 c) external view returns (uint256 minAmount, uint256 maxAmount) { return (minByIconCount[c], maxByIconCount[c]); }
    function getBurnParams() external view returns (address _burnWallet, uint256 _burnBpsOther) { return (burnWallet, burnBpsOther); }

    // -------- INTERNAL --------

    /**
     * @dev Transfers $PYTHIA, routing the 1% portion to burn or charity based on user's choice.
     * @param amount The gross amount wagered in $PYTHIA.
     * @param count The number of symbols (2-5).
     * @param drawId The ID of the draw.
     * @param sendToCharity The user's choice for the 1% destination.
     * @return net The net amount after deductions, which remains in the contract.
     */
    function _collectAndRoute(
        uint256 amount,
        uint8 count,
        uint256 drawId,
        bool sendToCharity 
    ) internal returns (uint256 net) {
        require(token.transferFrom(msg.sender, address(this), amount), "OffersLogic: transferFrom");
        
        if (count == 5) {
            require(token.transfer(burnWallet, amount), "OffersLogic: burn");
            emit TokensBurned(msg.sender, drawId, count, amount);
            return 0;
        }

        uint256 designatedAmount = (amount * burnBpsOther) / BPS_DENOMINATOR;
        
        if (designatedAmount > 0) {
           
            if (sendToCharity) {
                require(charityWallet != address(0), "OffersLogic: charity wallet not set");
                require(token.transfer(charityWallet, designatedAmount), "OffersLogic: charity transfer failed");
                emit DonationMade(msg.sender, drawId, designatedAmount);
            } else {
                require(token.transfer(burnWallet, designatedAmount), "OffersLogic: burn failed");
                emit TokensBurned(msg.sender, drawId, count, designatedAmount);
            }
            
        }

        uint256 fee = (amount * feeBps) / BPS_DENOMINATOR;
        if (fee > 0) { require(token.transfer(feeWallet, fee), "OffersLogic: fee"); }
        
        unchecked { return amount - designatedAmount - fee; }
    }

    function _recordOffer(uint256 drawId, uint256 amount, uint256 netAmount, uint8[] calldata icons) internal returns (uint256 offerIndex) {
        return offersData.processNewOffer(drawId, msg.sender, amount, netAmount, icons);
    }

    function _calculatePayout(uint8[] memory userIcons, uint8[5] memory winningIcons, uint256 amount) internal pure returns (uint256) {
        uint8 n = uint8(userIcons.length); if (n < 2) return 0;
        uint8 matches = 0; bool[91] memory win;
        for (uint i = 0; i < 5; i++) { win[winningIcons[i]] = true; }
        for (uint i = 0; i < n; i++) { if (win[userIcons[i]]) matches++; }
        if (matches != n) return 0;
        if (n == 2) return amount * MULT_2;
        if (n == 3) return amount * MULT_3;
        if (n == 4) return amount * MULT_4;
        if (n == 5) return amount * MULT_5;
        return 0;
    }

    function _validateIcons(uint8[] calldata icons, uint8 count) internal pure {
        if (count < 2 || count > 5) revert InvalidIconCount();
        uint128 seen;
        for (uint i = 0; i < count; i++) {
            uint8 v = icons[i]; if (v < 1 || v > 90) revert IconOutOfRange();
            uint128 m = uint128(1) << (v - 1); if ((seen & m) != 0) revert DuplicateIcon(); seen |= m;
        }
    }
}
