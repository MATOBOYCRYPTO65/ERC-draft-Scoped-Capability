# ERC-draft-Scoped-Capability
ERC draft: Scoped Capability Tokens for STVA

contract ScopedCapabilityToken {
    struct Binding {
        address target;
        bytes4 selector;
        bytes32 dataHash; // keccak256(data)
        uint256 value;
    }

    struct Capability {
        address issuer;
        address subject;
        bytes32 scope;
        uint48 validAfter;
        uint48 validUntil;
        uint256 nonce;
        Binding binding;
        bytes32 simulationResultHash;
        bytes32 intentHash;
        uint256 chainId;
    }

    // Nonce tracking for replay protection
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 private constant BINDING_TYPEHASH =
        keccak256(
            "Binding(address target,bytes4 selector,bytes32 dataHash,uint256 value)"
        );

    bytes32 private constant CAPABILITY_TYPEHASH =
        keccak256(
            "Capability(address issuer,address subject,bytes32 scope,uint48 validAfter,uint48 validUntil,uint256 nonce,Binding binding,bytes32 simulationResultHash,bytes32 intentHash,uint256 chainId)"
        );

    string public constant NAME = "ScopedCapabilityToken";
    string public constant VERSION = "1";

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function hashBinding(Binding memory binding) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                BINDING_TYPEHASH,
                binding.target,
                binding.selector,
                binding.dataHash,
                binding.value
            )
        );
    }

    function hashCapability(Capability memory cap) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        CAPABILITY_TYPEHASH,
                        cap.issuer,
                        cap.subject,
                        cap.scope,
                        cap.validAfter,
                        cap.validUntil,
                        cap.nonce,
                        hashBinding(cap.binding),
                        cap.simulationResultHash,
                        cap.intentHash,
                        cap.chainId
                    )
                )
            )
        );
    }

    function verifyCapability(
        Capability memory cap,
        bytes memory sig,
        address target,
        bytes4 selector,
        bytes memory data,
        uint256 value
    ) public returns (bool) {
        if (msg.sender != cap.subject) return false;

        if (usedNonces[cap.issuer][cap.nonce]) return false;
        if (block.timestamp < cap.validAfter || block.timestamp > cap.validUntil) return false;
        if (cap.chainId != block.chainid) return false;

        if (cap.binding.target != target) return false;
        if (cap.binding.selector != selector) return false;
        if (cap.binding.dataHash != keccak256(data)) return false;
        if (cap.binding.value != value) return false;

        if (sig.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;

        address recovered = ecrecover(hashCapability(cap), v, r, s);
        if (recovered != cap.issuer) return false;

        usedNonces[cap.issuer][cap.nonce] = true;
        return true;
    }
}
