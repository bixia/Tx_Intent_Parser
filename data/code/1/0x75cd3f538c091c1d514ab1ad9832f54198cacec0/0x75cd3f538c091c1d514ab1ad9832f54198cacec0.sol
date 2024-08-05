// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.21;

/// @title Gnars HD
/// @notice High definition Gnars counterparts
/// @author Volky
/// @dev This contract describes Gnars HD as 1:1 counterparts for each GnarV2. They are not mintable, since the ownership of the respective GnarV2 is mirrored on the GnarHD.
///
////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                        //
//                                                                                        //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀       ▀▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀   ▄▄░░░░▄   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀▀       ▀▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀  ▄▒░░░░░░░░░▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀  ▄▐▒░░░░   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▀  ▀░▐░░░░░░░░▌▐  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▄▒░░░░░░░▐   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▌░ ░░░░░░░░░░▓  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▄░░░░░░░░░▌▌  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▄▒ ▒░░░░░░░░░░▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▐░ ░░░░░░▐▐▌▌  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓   ░ ▐░░░░░░░░░░▓   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▌ ▐░░░░░░░░░▓   ▓▓▓▓▓▓▓▓▓▓▓▓   ▓▒ ░░░░░░░░░░▐   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▒ ░░░░░░░░░░▐   ▓▓▓▓▓▓▓▓▓▓▓▓   ▌░▒░░░░░░░░░░▌  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▒ ░░░░░░░░░░▐   ▓▓▀▀▀         ▐░ ░░░░░░░░░░▐   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▒ ▐░░░░░░░░░░        ▄▄▄▄▄▄▄▄▄▐░░░░░░░░░░░░▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▌░▐░░░░░░░░░░▌   ▐░ ░░░░░░░░░░▌░░░░░░░░░░░▐  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▐░ ▒░░░░░░░░░░▄▄░░░░░░░░░░░░░░▌░░░░░░░░░░▌▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▌▒░░░░░░░░░░░▓░░░░░░░░░░░░░░░▌░░░░░░░░░░▒▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▒░░░░░░░░░░░▌░░░░░▄▄▀▀▀▀▀▀▀▀▀▒░░░░░░░░░▀▄   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▐░░░░░░░░░░░▌░░░░▀░░░░░░░░░░░░░░░░░░░░░░░░▌  ▀▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▐░░░░░░░░░░▒░░░▌▒▒░░░░░░░░░░░░░░░░░░░░░░░░▀  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▐░░░░░░░░░▒░░░▌▄▐░░░░░░░░░░░░░░░░░░░░░░░░▒▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▒░░░░░░░░▓░░░░▓░▄░▀▒░░░░░░░░░░░░░░░░░░░▒▐▐  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ░░░░░░░░░░▌░░░░░▀▀▒▄▄▄▄▄▄▄▓▀▀▒░░░░░░░░░░░▐  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▐░░░░░░░░░░░▒▀▄▄░▄▄░▀░░░░░░░░░░░░░░░░░░░░░▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▐░░░░░░░░░░░░░░░░▓░░░░░░░░░░░░░░░░░░░░░░░▌  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▒░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░░░░░░░░░░▀  ▐▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▐░░░░░░░░░░░░░░░▒░░░░░░░░░░░░░░░░░░░░▄▀  ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌   ▒░░░░░░░░░░░░░▀▒░░░░░░░░░░░░░░░░░▒▀  ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   █▀▀▄▄▄░░░░░░░░░▀▄░░░░░░░░░░░▄▄█   ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▌  ▐░░░░░░░░░░░░░░░░░▒▀▀▀▀▀▀▒░░░░▐   ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   ▀░░░░░░░░░░░░░░░░░░░░░░░░░▄▀  ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▄   ▀▀▒▄░░░░░░░░░░░░░░░▒▀▀   ▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▄                     ▄▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▄▄▄▄▄▄▄▄▄▄▄▄▄▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓    //
//                                                                                        //
//              ░██████╗░███╗░░██╗░█████╗░██████╗░░██████╗  ██╗░░██╗██████╗░              //
//              ██╔════╝░████╗░██║██╔══██╗██╔══██╗██╔════╝  ██║░░██║██╔══██╗              //
//              ██║░░██╗░██╔██╗██║███████║██████╔╝╚█████╗░  ███████║██║░░██║              //
//              ██║░░╚██╗██║╚████║██╔══██║██╔══██╗░╚═══██╗  ██╔══██║██║░░██║              //
//              ╚██████╔╝██║░╚███║██║░░██║██║░░██║██████╔╝  ██║░░██║██████╔╝              //
//              ░╚═════╝░╚═╝░░╚══╝╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░  ╚═╝░░╚═╝╚═════╝░              //
//                                                                                        //
//                                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////

import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import {Owned} from "solmate/auth/Owned.sol";
import {Base64} from "base64/base64.sol";

contract GnarsHD is Owned {
    /* ⌐◨—————————————————————————————————————————————————————————————◨
                         STRUCTS / EVENTS / ERRORS
       ⌐◨—————————————————————————————————————————————————————————————◨ */
    struct Artwork {
        string ipfsFolder;
        uint48 amountBackgrounds;
        uint48 amountBodies;
        uint48 amountAccessories;
        uint48 amountHeads;
        uint48 amountNoggles;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);

    error Untransferable();
    error TokenDoesNotExist(uint256 tokenId);

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                         STORAGE
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    string public name = "Gnars HD";

    string public symbol = "GNARSHD";

    string public rendererBaseUri;

    string public contractURI;

    Artwork public artwork;

    ISkateContractV2 public gnarsV2;

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                        CONSTRUCTOR
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    constructor(
        address _gnarsV2Address,
        string memory _rendererBaseUri,
        Artwork memory _artwork,
        string memory _contractURI,
        address _owner
    ) Owned(_owner) {
        gnarsV2 = ISkateContractV2(_gnarsV2Address);
        rendererBaseUri = _rendererBaseUri;
        artwork = _artwork;
        contractURI = _contractURI;
    }

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                         MAIN LOGIC
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    function setArtwork(Artwork memory _artwork) public onlyOwner {
        artwork = _artwork;
    }

    function setContractUri(string memory _contractURI) public onlyOwner {
        contractURI = _contractURI;
    }

    function setRendererBaseUri(string memory _rendererBaseUri) public onlyOwner {
        rendererBaseUri = _rendererBaseUri;
    }

    /// @notice The properties and query string for a generated token
    /// @param _tokenId The ERC-721 token id
    function getAttributes(uint256 _tokenId)
        public
        view
        returns (string memory resultAttributes, string memory queryString)
    {
        (uint48 background, uint48 body, uint48 accessory, uint48 head, uint48 glasses) = gnarsV2.seeds(_tokenId);
        IGnarDescriptorV2 descriptor = IGnarDescriptorV2(gnarsV2.descriptor());
        IGnarDecorator decorator = IGnarDecorator(descriptor.decorator());

        queryString = string.concat(
            "?contractAddress=",
            Strings.toHexString(address(this)),
            "&tokenId=",
            Strings.toString(_tokenId),
            getBackgroundQueryParam(background),
            getPartQueryParam("BODY", body, artwork.amountBodies),
            getPartQueryParam("ACCESSORY", accessory, artwork.amountAccessories),
            getPartQueryParam("HEADS", head, artwork.amountHeads),
            getPartQueryParam("NOGGLES", glasses, artwork.amountNoggles)
        );

        resultAttributes = string.concat(
            getPartTrait("Background", background, decorator.backgrounds),
            ",",
            getPartTrait("Body", body, decorator.bodies),
            ",",
            getPartTrait("Accessory", accessory, decorator.accessories),
            ",",
            getPartTrait("Head", head, decorator.heads),
            ",",
            getPartTrait("Glasses", glasses, decorator.glasses)
        );
    }

    function getPartQueryParam(string memory folder, uint48 partIndex, uint48 amountOfPart)
        public
        view
        returns (string memory)
    {
        if (partIndex >= amountOfPart) {
            return string.concat("&images=", artwork.ipfsFolder, "/", folder, "/FALLBACK.PNG");
        }

        return string.concat("&images=", artwork.ipfsFolder, "/", folder, "/", Strings.toString(partIndex), ".PNG");
    }

    function getBackgroundQueryParam(uint48 backgroundIndex) public view returns (string memory) {
        if (backgroundIndex >= artwork.amountBackgrounds) {
            return string.concat("&images=", artwork.ipfsFolder, "/BACKGROUND/FALLBACK.PNG");
        }

        return string.concat("&images=", artwork.ipfsFolder, "/BACKGROUND/", Strings.toString(backgroundIndex), ".PNG");
    }

    function getPartTrait(
        string memory traitType,
        uint48 partIndex,
        function (uint256) external view returns (string memory) getPartDescription
    ) public view returns (string memory) {
        try getPartDescription(partIndex) returns (string memory partDescription) {
            return string.concat('{"trait_type":"', traitType, '","value":"', partDescription, '"}');
        } catch {
            return string.concat('{"trait_type":"', traitType, '","value":"Unknown"}');
        }
    }

    function tokenURI(uint256 _tokenId) public view returns (string memory) {
        if (gnarsV2.ownerOf(_tokenId) == address(0)) {
            revert TokenDoesNotExist(_tokenId);
        }

        (string memory attributes, string memory queryString) = getAttributes(_tokenId);
        return string(
            abi.encodePacked(
                "data:application/json;base64,",
                Base64.encode(
                    bytes(
                        abi.encodePacked(
                            '{"name":"Gnar HD #',
                            Strings.toString(_tokenId),
                            '", "description":"High definition Gnar #',
                            Strings.toString(_tokenId),
                            " counterpart",
                            '", "attributes": [',
                            attributes,
                            '], "image": "',
                            string.concat(rendererBaseUri, queryString),
                            '"}'
                        )
                    )
                )
            )
        );
    }

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                              PASSTHROUGH METHODS
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    /// @notice Returns the total amount of Gnars HD in existence
    /// @dev Delegates to the Gnars V2 contract
    function totalSupply() external view returns (uint256) {
        return gnarsV2.totalSupply();
    }

    /// @notice Returns the tokenId of the Gnar HD by index
    /// @dev Delegates to the Gnars V2 contract
    function tokenByIndex(uint256 _index) external view returns (uint256) {
        return gnarsV2.tokenByIndex(_index);
    }

    /// @notice Returns the Gnar HD owner's address by token index
    /// @dev Delegates to the Gnars V2 contract
    function tokenOfOwnerByIndex(address _owner, uint256 _index) external view returns (uint256) {
        return gnarsV2.tokenOfOwnerByIndex(_owner, _index);
    }

    /// @notice Returns the Gnar HD owner's address by token id
    /// @dev Delegates to the Gnars V2 contract
    function ownerOf(uint256 id) public view returns (address owner) {
        return gnarsV2.ownerOf(id);
    }

    /// @notice Returns the amount of Gnars HD owned by the specified address
    /// @dev Delegates to the Gnars V2 contract
    function balanceOf(address owner) public view returns (uint256) {
        return gnarsV2.balanceOf(owner);
    }

    /// @notice Refresh ownership of specified tokens on marketplaces/datasets that are showing out of date information
    /// @dev Since this token is not mintable, there's no Transfer event. This method emits the Transfer event so that consumers that can detect the creation/new ownership of the token.
    /// @param tokenIds The ids of tokens to refresh
    function assertOwnership(uint256[] memory tokenIds) public {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            emit Transfer(address(0), gnarsV2.ownerOf(tokenId), tokenId);
        }
    }

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                              ERC721 LOGIC
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    /// @notice Gnars HD are not transferable
    /// @dev Will always revert
    function approve(address, uint256) public pure {
        revert Untransferable();
    }

    /// @notice Gnars HD are not transferable
    /// @dev Will always revert
    function setApprovalForAll(address, bool) public pure {
        revert Untransferable();
    }

    /// @notice Gnars HD are not transferable
    /// @dev Will always revert
    function transferFrom(address, address, uint256) public pure {
        revert Untransferable();
    }

    /// @notice Gnars HD are not transferable
    /// @dev Will always revert
    function safeTransferFrom(address, address, uint256) public pure {
        revert Untransferable();
    }

    /// @notice Gnars HD are not transferable
    /// @dev Will always revert
    function safeTransferFrom(address, address, uint256, bytes calldata) public pure {
        revert Untransferable();
    }

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                              ERC6454 LOGIC
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    /// @notice Gnars HD are not transferable
    /// @dev Will always return false
    function isTransferable(uint256, address, address) external pure returns (bool) {
        return false;
    }

    /* ⌐◨—————————————————————————————————————————————————————————————◨
                              ERC165 LOGIC
       ⌐◨—————————————————————————————————————————————————————————————◨ */

    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == 0x01ffc9a7 // ERC165 Interface ID for ERC165
            || interfaceId == 0x80ac58cd // ERC165 Interface ID for ERC721
            || interfaceId == 0x5b5e139f // ERC165 Interface ID for ERC721Metadata
            || interfaceId == 0x780e9d63 // ERC165 Interface ID for ERC721Enumerable
            || interfaceId == 0x7f5828d0 // ERC165 Interface ID for ERC173
            || interfaceId == 0x91a6262f; // ERC165 Interface ID for ERC6454
    }
}

interface IGnarDecorator {
    function accessories(uint256) external view returns (string memory);
    function backgrounds(uint256) external view returns (string memory);
    function bodies(uint256) external view returns (string memory);
    function glasses(uint256) external view returns (string memory);
    function heads(uint256) external view returns (string memory);
}

interface IGnarDescriptorV2 {
    function decorator() external view returns (address);
}

interface ISkateContractV2 {
    function balanceOf(address owner) external view returns (uint256);
    function descriptor() external view returns (address);
    function ownerOf(uint256 tokenId) external view returns (address);
    function seeds(uint256)
        external
        view
        returns (uint48 background, uint48 body, uint48 accessory, uint48 head, uint48 glasses);
    function tokenByIndex(uint256 index) external view returns (uint256);
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)

pragma solidity ^0.8.0;

import "./math/Math.sol";
import "./math/SignedMath.sol";

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            /// @solidity memory-safe-assembly
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toString(int256 value) internal pure returns (string memory) {
        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}

// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0;

/// @title Base64
/// @author Brecht Devos - <brecht@loopring.org>
/// @notice Provides functions for encoding/decoding base64
library Base64 {
    string internal constant TABLE_ENCODE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    bytes  internal constant TABLE_DECODE = hex"0000000000000000000000000000000000000000000000000000000000000000"
                                            hex"00000000000000000000003e0000003f3435363738393a3b3c3d000000000000"
                                            hex"00000102030405060708090a0b0c0d0e0f101112131415161718190000000000"
                                            hex"001a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132330000000000";

    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return '';

        // load the table into memory
        string memory table = TABLE_ENCODE;

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((data.length + 2) / 3);

        // add some extra buffer at the end required for the writing
        string memory result = new string(encodedLen + 32);

        assembly {
            // set the actual output length
            mstore(result, encodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 3 bytes at a time
            for {} lt(dataPtr, endPtr) {}
            {
                // read 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // write 4 characters
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr( 6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(        input,  0x3F))))
                resultPtr := add(resultPtr, 1)
            }

            // padding with '='
            switch mod(mload(data), 3)
            case 1 { mstore(sub(resultPtr, 2), shl(240, 0x3d3d)) }
            case 2 { mstore(sub(resultPtr, 1), shl(248, 0x3d)) }
        }

        return result;
    }

    function decode(string memory _data) internal pure returns (bytes memory) {
        bytes memory data = bytes(_data);

        if (data.length == 0) return new bytes(0);
        require(data.length % 4 == 0, "invalid base64 decoder input");

        // load the table into memory
        bytes memory table = TABLE_DECODE;

        // every 4 characters represent 3 bytes
        uint256 decodedLen = (data.length / 4) * 3;

        // add some extra buffer at the end required for the writing
        bytes memory result = new bytes(decodedLen + 32);

        assembly {
            // padding with '='
            let lastBytes := mload(add(data, mload(data)))
            if eq(and(lastBytes, 0xFF), 0x3d) {
                decodedLen := sub(decodedLen, 1)
                if eq(and(lastBytes, 0xFFFF), 0x3d3d) {
                    decodedLen := sub(decodedLen, 1)
                }
            }

            // set the actual output length
            mstore(result, decodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 4 characters at a time
            for {} lt(dataPtr, endPtr) {}
            {
               // read 4 characters
               dataPtr := add(dataPtr, 4)
               let input := mload(dataPtr)

               // write 3 bytes
               let output := add(
                   add(
                       shl(18, and(mload(add(tablePtr, and(shr(24, input), 0xFF))), 0xFF)),
                       shl(12, and(mload(add(tablePtr, and(shr(16, input), 0xFF))), 0xFF))),
                   add(
                       shl( 6, and(mload(add(tablePtr, and(shr( 8, input), 0xFF))), 0xFF)),
                               and(mload(add(tablePtr, and(        input , 0xFF))), 0xFF)
                    )
                )
                mstore(resultPtr, shl(232, output))
                resultPtr := add(resultPtr, 3)
            }
        }

        return result;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)

pragma solidity ^0.8.0;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Down, // Toward negative infinity
        Up, // Toward infinity
        Zero // Toward zero
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds up instead
     * of rounding down.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)
     * with further edits by Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division.
            if (prod1 == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return prod0 / denominator;
            }

            // Make sure the result is less than 2^256. Also prevents denominator == 0.
            require(denominator > prod1, "Math: mulDiv overflow");

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            uint256 remainder;
            assembly {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.
            // See https://cs.stackexchange.com/q/138556/92363.

            // Does not overflow because the denominator cannot be zero at this stage in the function.
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such
            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv = 1 mod 2^4.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works
            // in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2^8
            inverse *= 2 - denominator * inverse; // inverse mod 2^16
            inverse *= 2 - denominator * inverse; // inverse mod 2^32
            inverse *= 2 - denominator * inverse; // inverse mod 2^64
            inverse *= 2 - denominator * inverse; // inverse mod 2^128
            inverse *= 2 - denominator * inverse; // inverse mod 2^256

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is
            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inverse;
            return result;
        }
    }

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.
     *
     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.
        //
        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have
        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.
        //
        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`
        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`
        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`
        //
        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.
        uint256 result = 1 << (log2(a) >> 1);

        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,
        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at
        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision
        // into the expected uint128 result.
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }

    /**
     * @notice Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256, rounded down, of a positive value.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);
        }
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)

pragma solidity ^0.8.0;

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // must be unchecked in order to support `n = type(int256).min`
            return uint256(n >= 0 ? n : -n);
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Simple single owner authorization mixin.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Owned.sol)
abstract contract Owned {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event OwnershipTransferred(address indexed user, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                            OWNERSHIP STORAGE
    //////////////////////////////////////////////////////////////*/

    address public owner;

    modifier onlyOwner() virtual {
        require(msg.sender == owner, "UNAUTHORIZED");

        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _owner) {
        owner = _owner;

        emit OwnershipTransferred(address(0), _owner);
    }

    /*//////////////////////////////////////////////////////////////
                             OWNERSHIP LOGIC
    //////////////////////////////////////////////////////////////*/

    function transferOwnership(address newOwner) public virtual onlyOwner {
        owner = newOwner;

        emit OwnershipTransferred(msg.sender, newOwner);
    }
}

