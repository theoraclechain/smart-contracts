/**
 *Submitted for verification at testnet.bscscan.com on 2025-09-06
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ========================================================================== */
/*                      Minimal OpenZeppelin-like (Flattened)                  */
/* ========================================================================== */
abstract contract Context { function _msgSender() internal view virtual returns (address) { return msg.sender; } }

interface IERC165 { function supportsInterface(bytes4 interfaceId) external view returns (bool); }

abstract contract ERC165 is IERC165 {
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2); buffer[0] = "0"; buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) { buffer[i] = _SYMBOLS[value & 0xf]; value >>= 4; }
        return string(buffer);
    }
    function toHexString(address value) internal pure returns (string memory) { return toHexString(uint256(uint160(value)), 20); }
}

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

abstract contract AccessControl is Context, ERC165, IAccessControl {
    struct RoleData { mapping(address => bool) members; bytes32 adminRole; }
    mapping(bytes32 => RoleData) private _roles;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId || super.supportsInterface(interfaceId);
    }
    function hasRole(bytes32 role, address account) public view virtual override returns (bool) { return _roles[role].members[account]; }
    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) {
        bytes32 admin = _roles[role].adminRole; return admin == bytes32(0) ? DEFAULT_ADMIN_ROLE : admin;
    }
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 prev = _roles[role].adminRole; _roles[role].adminRole = adminRole; emit RoleAdminChanged(role, prev, adminRole);
    }
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert(string(abi.encodePacked("AccessControl: account ", Strings.toHexString(account), " is missing role ", Strings.toHexString(uint256(role), 32))));
        }
    }
    function _grantRole(bytes32 role, address account) internal virtual {
        if (!hasRole(role, account)) { _roles[role].members[account] = true; emit RoleGranted(role, account, _msgSender()); }
    }
    function _revokeRole(bytes32 role, address account) internal virtual {
        if (hasRole(role, account)) { _roles[role].members[account] = false; emit RoleRevoked(role, account, _msgSender()); }
    }
    function grantRole(bytes32 role, address account) external virtual override { _checkRole(getRoleAdmin(role), _msgSender()); _grantRole(role, account); }
    function revokeRole(bytes32 role, address account) external virtual override { _checkRole(getRoleAdmin(role), _msgSender()); _revokeRole(role, account); }
    function renounceRole(bytes32 role, address account) external virtual override { require(account == _msgSender(), "AccessControl: can only renounce for self"); _revokeRole(role, account); }
}

/* ========================================================================== */
/*                           Icons PRNG (deterministic)                        */
/* ========================================================================== */
/**
 * @title OracleIconsV1 — Uniform, unique, sorted icons (1..90)
 * @notice Pure, unbiased icon derivation from a 32-byte seed.
 * @dev Rejection sampling avoids modulo bias. Output is sorted ascending and unique.
 */
library OracleIconsV1 {
    bytes constant private TAG = "ICON_PRNG_V1";
    uint256 constant private MOD = 90;
    uint256 constant private LIMIT = type(uint256).max - (type(uint256).max % MOD);

    /// @notice Deterministically derive 5 icons in range [1..90], unique and sorted.
    /// @param seed 32-byte seed.
    /// @return out Array of five icon ids.
    function getIconsFromSeed(bytes32 seed) internal pure returns (uint8[5] memory out) {
        bytes32 state = keccak256(abi.encodePacked(TAG, seed));
        bool[91] memory used; // 1..90
        uint8 k = 0;
        while (k < 5) {
            uint256 r = uint256(state);
            if (r > LIMIT) { state = keccak256(abi.encodePacked(TAG, state, bytes1(0x01))); continue; }
            uint8 v = uint8((r % MOD) + 1);
            if (used[v]) { state = keccak256(abi.encodePacked(TAG, state, bytes1(0x02))); continue; }
            used[v] = true; out[k] = v; unchecked { ++k; }
            state = keccak256(abi.encodePacked(TAG, state, bytes1(0x00)));
        }
        // selection-sort ascending (5 elements)
        for (uint8 i = 0; i < 5; ++i) {
            uint8 m = i;
            for (uint8 j = i + 1; j < 5; ++j) { if (out[j] < out[m]) m = j; }
            if (m != i) { uint8 t = out[i]; out[i] = out[m]; out[m] = t; }
        }
    }
}

/* ========================================================================== */
/*                               OracleRevelation                             */
/* ========================================================================== */
contract OracleRevelation is AccessControl {
    using OracleIconsV1 for bytes32;

    /* ----------------------------- Roles/const ----------------------------- */
    bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
    uint64  public constant BLOCK_OFFSET   = 17; // target = anchoredAt + 17

    /* -------------------------------- Types -------------------------------- */
    struct Revelation {
        uint256 drawId;
        uint64  deadline;
        uint64  publishedAt;
        uint64  blockNumberUsed;
        bytes32 blockHashUsed;
        bytes32 masterKeyHash;  // first draw: set at openDraw; next draws: previous seed copied at publish
        bytes32 seed;           // derived at publish
        uint64  targetBlock;    // set by anchorTargetBlock(); 0 if not anchored yet
        bool    scheduled;
        bool    revealed;
        bool    cancelled;
        string  publisherNote;
    }

    /* -------------------------------- State -------------------------------- */
    mapping(uint256 => Revelation) private _revelations;

    uint256 public lastPublishedDrawId;     // last revealed
    uint256 public lastScheduledDrawId;     // last scheduled (open)
    uint256 public currentOpenDrawId;       // 0 if none open

    bool private _openedOnce;               // one-shot guard for openDraw

    /* -------------------------------- Events ------------------------------- */
    event DrawsOpened(uint256 indexed firstDrawId, uint64 deadline, bytes32 masterKeyHash);
    event DrawScheduled(uint256 indexed drawId, uint64 deadline, string publisherNote);
    event TargetAnchored(uint256 indexed drawId, uint64 anchoredAtBlock, uint64 targetBlock);
    event RevelationPublished(
        uint256 indexed drawId,
        uint8[5] icons,
        uint64 blockNumberUsed,
        bytes32 blockHashUsed,
        bytes32 masterKeyHash,
        bytes32 seed,
        uint64 deadline,
        string publisherNote,
        uint64 publishedAt
    );
    event DrawCancelled(uint256 indexed drawId, string reason, uint64 cancelledAt);
    event PublisherNoteUpdated(uint256 indexed drawId, string newNote);

    /* ------------------------------ Modifiers ------------------------------ */
    modifier onlyRole(bytes32 role) { _checkRole(role, _msgSender()); _; }

    /* ------------------------------ Constructor ---------------------------- */
    constructor(address admin, address initialPublisher) {
        require(admin != address(0), "Oracle: admin=0");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        if (initialPublisher != address(0)) _grantRole(PUBLISHER_ROLE, initialPublisher);
    }

    /* ---------------------------- One-shot open ---------------------------- */
    /// @notice One-shot: opens the very first draw (id=1), setting its masterKeyHash and deadline.
    function openDraw(bytes32 masterKeyHash, uint64 deadline) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!_openedOnce, "Oracle: already opened");
        require(currentOpenDrawId == 0 && lastScheduledDrawId == 0 && lastPublishedDrawId == 0, "Oracle: initialized");
        require(masterKeyHash != bytes32(0), "Oracle: masterKey=0");
        require(deadline > block.timestamp, "Oracle: deadline in past");

        uint256 drawId = 1;
        Revelation storage r = _revelations[drawId];
        require(!r.scheduled && !r.revealed && !r.cancelled, "Oracle: exists");

        r.drawId = drawId;
        r.deadline = deadline;
        r.masterKeyHash = masterKeyHash; // first/master key goes here
        r.scheduled = true;

        lastScheduledDrawId = drawId;
        currentOpenDrawId   = drawId;
        _openedOnce = true;

        emit DrawScheduled(drawId, deadline, "");
        emit DrawsOpened(drawId, deadline, masterKeyHash);
    }

    /* ------------------------------ Scheduling ----------------------------- */
    /// @notice Schedule the next draw (only if none is currently open). Publisher-only.
    function scheduleDraw(uint256 drawId, uint64 deadline, string calldata publisherNote)
        external onlyRole(PUBLISHER_ROLE)
    {
        require(_openedOnce, "Oracle: call openDraw first");
        require(currentOpenDrawId == 0, "Oracle: another draw open");
        uint256 expected = (lastPublishedDrawId == 0) ? 2 : (lastPublishedDrawId + 1);
        require(drawId == expected, "Oracle: drawId must be next");
        require(deadline > block.timestamp, "Oracle: deadline in past");

        Revelation storage r = _revelations[drawId];
       require((!r.scheduled && !r.revealed) || r.cancelled, "Oracle: draw exists and is not cancelled");

        r.drawId = drawId;
        r.deadline = deadline;
        r.publisherNote = publisherNote;
        r.scheduled = true;

        lastScheduledDrawId = drawId;
        currentOpenDrawId   = drawId;

        emit DrawScheduled(drawId, deadline, publisherNote);
    }

    /// @notice Admin can update the note of a scheduled draw.
    function updatePublisherNote(uint256 drawId, string calldata newNote) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Revelation storage r = _revelations[drawId];
        require(r.scheduled, "Oracle: not scheduled");
        r.publisherNote = newNote;
        emit PublisherNoteUpdated(drawId, newNote);
    }

    /// @notice Admin can update deadline while open and not revealed/cancelled.
    function updateDeadline(uint256 drawId, uint64 newDeadline) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Revelation storage r = _revelations[drawId];
        require(r.scheduled && !r.revealed && !r.cancelled, "Oracle: not open");
        require(newDeadline > block.timestamp, "Oracle: deadline in past");
        r.deadline = newDeadline;
        emit DrawScheduled(drawId, newDeadline, r.publisherNote); // reuse event as update signal (or add a dedicated one)
    }

    /// @notice Admin can cancel an open draw.
    function cancelDraw(uint256 drawId, string calldata reason) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Revelation storage r = _revelations[drawId];
        require(r.scheduled && !r.revealed && !r.cancelled, "Oracle: not cancellable");
        r.cancelled = true;
        if (currentOpenDrawId == drawId) currentOpenDrawId = 0;
        if (bytes(reason).length > 0) r.publisherNote = reason;
        emit DrawCancelled(drawId, reason, uint64(block.timestamp));
    }

    /* ------------------------------- Anchor -------------------------------- */
    /// @notice After the deadline, anchor the target block once (target = current + BLOCK_OFFSET).
    /// @dev Publisher-only to avoid spam; keep expireIfTargetStale permissionless for liveness.
    function anchorTargetBlock() external onlyRole(PUBLISHER_ROLE) {
        uint256 id = currentOpenDrawId;
        require(id != 0, "Oracle: no open draw");
        Revelation storage r = _revelations[id];
        require(r.scheduled && !r.revealed && !r.cancelled, "Oracle: not open");
        require(r.targetBlock == 0, "Oracle: target set");
        require(block.timestamp >= r.deadline, "Oracle: too early");
        uint64 anchored = uint64(block.number);
        r.targetBlock = anchored + BLOCK_OFFSET;
        emit TargetAnchored(id, anchored, r.targetBlock);
    }

    /* ------------------------------ Revelation ----------------------------- */
    /// @notice Publish the revelation for the only open draw. Requires anchored target block.
    /// @param blockNumberUsed Must equal the anchored targetBlock.
    /// @param claimedBlockHash Hash of the target block; will be verified on-chain.
    function publishRevelation(uint64 blockNumberUsed, bytes32 claimedBlockHash)
        external onlyRole(PUBLISHER_ROLE)
    {
        uint256 drawId = currentOpenDrawId;
        require(drawId != 0, "Oracle: no open draw");
        Revelation storage r = _revelations[drawId];

        require(r.scheduled && !r.revealed && !r.cancelled, "Oracle: invalid state");
        require(block.timestamp >= r.deadline, "Oracle: too early");

        // Target must be anchored and match the provided blockNumberUsed
        require(r.targetBlock != 0, "Oracle: target not set");
        require(blockNumberUsed == r.targetBlock, "Oracle: wrong target");

        // Verify blockhash availability and equality
        require(block.number > blockNumberUsed, "Oracle: future block");
        uint256 delta = uint256(block.number) - uint256(blockNumberUsed);
        require(delta <= 256, "Oracle: block too old");
        bytes32 actual = blockhash(uint256(blockNumberUsed));
        require(actual == claimedBlockHash && actual != bytes32(0), "Oracle: blockhash mismatch");

        // Master key used: first draw uses its masterKeyHash, subsequent draws use previous seed
        bytes32 masterKeyUsed = (lastPublishedDrawId == 0) ? r.masterKeyHash : _revelations[lastPublishedDrawId].seed;

        // Seed derivation
        bytes32 seed_ = keccak256(abi.encodePacked(masterKeyUsed, actual));

        // Persist
        r.blockNumberUsed = blockNumberUsed;
        r.blockHashUsed   = actual;
        r.masterKeyHash   = masterKeyUsed; // for audit trail
        r.seed            = seed_;
        r.publishedAt     = uint64(block.timestamp);
        r.revealed        = true;

        lastPublishedDrawId = drawId;
        currentOpenDrawId   = 0; // no open draw after publish

        // Derive icons on-the-fly for the event (not stored)
        uint8[5] memory icons = OracleIconsV1.getIconsFromSeed(seed_);

        emit RevelationPublished(
            drawId, icons, blockNumberUsed, actual, masterKeyUsed, seed_,
            r.deadline, r.publisherNote, r.publishedAt
        );
    }

    /* ----------------------------- Safety valve ---------------------------- */
    /// @notice Anyone can cancel the open draw if the anchored target block got stale (>256 blocks).
    function expireIfTargetStale() external {
        uint256 id = currentOpenDrawId;
        require(id != 0, "Oracle: no open draw");
        Revelation storage r = _revelations[id];
        require(r.scheduled && !r.revealed && !r.cancelled, "Oracle: not open");
        require(r.targetBlock != 0, "Oracle: target not set");
        require(block.number > uint256(r.targetBlock) + 256, "Oracle: within 256 blocks");
        r.cancelled = true;
        currentOpenDrawId = 0;
        emit DrawCancelled(id, "expired: blockhash unavailable", uint64(block.timestamp));
    }

    /* --------------------------------- Views ------------------------------- */
    function getRevelation(uint256 drawId) external view returns (Revelation memory) { return _revelations[drawId]; }

    function isScheduled(uint256 drawId) external view returns (bool) { return _revelations[drawId].scheduled; }
    function isRevealed(uint256 drawId)  external view returns (bool) { return _revelations[drawId].revealed; }
    function isCancelled(uint256 drawId) external view returns (bool) { return _revelations[drawId].cancelled; }

    function getLastPublished() external view returns (uint256) { return lastPublishedDrawId; }

    /// @notice Returns the only open draw if present.
    function currentOpenDraw() external view returns (bool exists_, uint256 drawId_, uint64 deadline_) {
        uint256 id = currentOpenDrawId;
        if (id != 0) {
            Revelation storage r = _revelations[id];
            if (r.scheduled && !r.revealed && !r.cancelled) { return (true, id, r.deadline); }
        }
        return (false, 0, 0);
    }

    /// @notice Returns the actually playable draw id now (0 if none).
    function nextPlayableDrawId() external view returns (uint256) { return currentOpenDrawId; }

    /// @notice Summary: (scheduled, cancelled, revealed, deadline, publishedAt, seed).
    function getStatusSummary(uint256 drawId) external view
        returns (bool scheduled, bool cancelled, bool revealed, uint64 deadline, uint64 publishedAt, bytes32 seed)
    {
        Revelation storage r = _revelations[drawId];
        return (r.scheduled, r.cancelled, r.revealed, r.deadline, r.publishedAt, r.seed);
    }

    /// @notice Derived icons for a revealed draw (reverts if not revealed).
    function getDerivedIcons(uint256 drawId) external view returns (uint8[5] memory) {
        Revelation storage r = _revelations[drawId];
        require(r.revealed, "Oracle: not revealed");
        return OracleIconsV1.getIconsFromSeed(r.seed);
    }

    /// @notice Getter for anchored target block (0 if not set).
    function getTargetBlock(uint256 drawId) external view returns (uint64) {
        return _revelations[drawId].targetBlock;
    }

    /// @notice Add/remove publisher role.
    function addPublisher(address a) external onlyRole(DEFAULT_ADMIN_ROLE) { _grantRole(PUBLISHER_ROLE, a); }
    function removePublisher(address a) external onlyRole(DEFAULT_ADMIN_ROLE) { _revokeRole(PUBLISHER_ROLE, a); }
}
