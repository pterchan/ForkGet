//! Exact fingerprints for reviewed, semantically identical migration encodings.

pub(super) struct Fingerprint {
    pub version: i64,
    pub canonical: &'static str,
    pub predecessors: &'static [&'static str],
}

pub(super) const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        version: 1,
        canonical: "1f3a146d6d161074d467326a301564ffeb50f90fadce3d664384e202c8e73c9c84894f9304a81ec1ce25459ee700c43f",
        predecessors: &[
            "1f3a146d6d161074d467326a301564ffeb50f90fadce3d664384e202c8e73c9c84894f9304a81ec1ce25459ee700c43f",
            "513b04dfb5308c87f4874ce17717756a6776fd6a17dca43cdc2d5f682f572bc0900a477a568de85ef277fd011a6ce662",
        ],
    },
    Fingerprint {
        version: 2,
        canonical: "37773bb89302ca58033f440f9af2e54cb48da6fd771aae859b6d79a4ae38809afdfb85c955523d5c1d16364e888eabe6",
        predecessors: &[
            "37773bb89302ca58033f440f9af2e54cb48da6fd771aae859b6d79a4ae38809afdfb85c955523d5c1d16364e888eabe6",
            "b4077c543ba44cdb5d2a2e5390148dd5d3879a54981cf679c947c8c49c5fe92a459ac50f061f8d3ea1d0742b4367b6e1",
        ],
    },
    Fingerprint {
        version: 3,
        canonical: "8997a8677dfe9ad4e876a33ea8909a336c135792719f56780a33f43d5d14d5adef673e9a4da3813718a077f0b8d29ea0",
        predecessors: &[
            "8997a8677dfe9ad4e876a33ea8909a336c135792719f56780a33f43d5d14d5adef673e9a4da3813718a077f0b8d29ea0",
            "96ba617a6c5bbde12e0f17d3a9972dbed3f01af62322740f9dff2a660ab54064245801efce258aeb89c0e6b387a70429",
        ],
    },
    Fingerprint {
        version: 4,
        canonical: "57c7793acb62a96e17eb38b49d2855afe5bb67e8933817884490616e4ec8b733cf01ffce91f3b79708686e15ec91d8b9",
        predecessors: &[
            "57c7793acb62a96e17eb38b49d2855afe5bb67e8933817884490616e4ec8b733cf01ffce91f3b79708686e15ec91d8b9",
            "7188b5c06972626405431060ad9541c7d4e64729b7d114f0077787b10fc585413071a6ddaeefe3dcd12c60fc25205178",
        ],
    },
    Fingerprint {
        version: 5,
        canonical: "6ffac5df4e24c5d82bab9791abb8806675007f4efcacebdb26c5cfd23083a1fc4c83ec5a0686e974ffa67061a064426c",
        predecessors: &[
            "6ffac5df4e24c5d82bab9791abb8806675007f4efcacebdb26c5cfd23083a1fc4c83ec5a0686e974ffa67061a064426c",
            "b602e085a17bffe0e2937a938c2d94949dee590f6da4fd8170dc9979934a61e44a6217f9749bfe29d51fd5455c4be0ab",
        ],
    },
    Fingerprint {
        version: 6,
        canonical: "0c93a35f6e0933be1dc4169da45b5ccbd6450096f0af8d3455a0347e6d616192e57a56df516b1c71329df8e84cfe435e",
        predecessors: &[
            "0c93a35f6e0933be1dc4169da45b5ccbd6450096f0af8d3455a0347e6d616192e57a56df516b1c71329df8e84cfe435e",
            "4e6cab98344e7b5566ce3636d9bd9b0a12920101117f09142076331393c050ec0b034e1f5b43bd2b664dcbc1edb1a5b0",
        ],
    },
    Fingerprint {
        version: 7,
        canonical: "9de6d0a248c5876d374eda1ff8ed5ac88ae56201dc0cb43838e44e5b202c6cb624b252f62a184761c630c0589861d96f",
        predecessors: &[
            "9de6d0a248c5876d374eda1ff8ed5ac88ae56201dc0cb43838e44e5b202c6cb624b252f62a184761c630c0589861d96f",
            "fe1686500357f0aa355936e23ceaadadc4ef8157cdd0f5b2469a8d369fdde1146160bd897df2b4485891400b209cf41b",
        ],
    },
    Fingerprint {
        version: 8,
        canonical: "9000b44b9e66d7f0f4643b38e540ee8e5fd22af08ed1b0a5deaf111cf1d8e99de6a322c28181823427b0fd038457c85a",
        predecessors: &[
            "9000b44b9e66d7f0f4643b38e540ee8e5fd22af08ed1b0a5deaf111cf1d8e99de6a322c28181823427b0fd038457c85a",
            "5d2116637babcb9715ed22bf852eb3ab23afc9740bf0dc58e3f07c7a4d0b1b2bd315d224459a09ca65514e6ec169df3f",
        ],
    },
    Fingerprint {
        version: 9,
        canonical: "88666b6f5a233093874bfa1444aa8f3cfc6dd0ce57c520381cf971f0520ba2a6737facbfa07b20061113da5973d8c9ad",
        predecessors: &[
            "88666b6f5a233093874bfa1444aa8f3cfc6dd0ce57c520381cf971f0520ba2a6737facbfa07b20061113da5973d8c9ad",
            "ccd33c0c197f2e772ddfeefb36cb40b25c27038a69a86018fa7906b3dbb99025d0db736fc3a160ced635238c249328e8",
        ],
    },
    Fingerprint {
        version: 10,
        canonical: "88a4713045b6c5c036c4ed28933b94c112788fa7bcf0ad6c10fb38afa65beb4c267d349309238c408a783d90c5732dc8",
        predecessors: &[
            "88a4713045b6c5c036c4ed28933b94c112788fa7bcf0ad6c10fb38afa65beb4c267d349309238c408a783d90c5732dc8",
            "a47f6506c22e84f43232759b4ae4405083a95ac6b24321ca95493da1d1f13782281ccad6afa1385e0f7c537be216fb10",
        ],
    },
    Fingerprint {
        version: 11,
        canonical: "a95d5c74d97cd5cdc46e9a78d326f02ab2592dacc261a2e8ffe760dad4cceca2b108c1505525cc478b182617316c2848",
        predecessors: &[
            "442dbb28ae4dfeea490461d39da2085d24153a9ca51f8b1a27887435394e4eba471370ab778ff7439e6976be0342048c",
            "76be6c578080cd456911bca859de9e19dc10b79cd17b8211fc9d0b011fde3f2dc743dece9fabd06d0819d219ea29aea2",
        ],
    },
    Fingerprint {
        version: 12,
        canonical: "bdda143c2c3283493f3d03a5106df6864d8b16c773361a16a24bd25d26e2f9a6f77cc0cc7079d3c144ac2982559021ae",
        predecessors: &[
            "eb17b0fc49ca58f9c3eaa31e83faba6c0b0dfe3a8d30deadb1a92ed3e76a997a60355870cf219dd07e86767c22b7e961",
            "7e6d6be9ff367069ecbf811d9e7d866f30c6cfa09dcba95c98d10bee7d908c8ec516fb64e7db7f1546745563ee3a58fe",
        ],
    },
    Fingerprint {
        version: 13,
        canonical: "9c1e0e3c68580f9b2d787ef1435fe2d084f684158fec971ea399ba257ef45157cb56124a6f0aca45c87b59c40e3bc1da",
        predecessors: &[
            "c03ff3ad8f27e089ff71325a29957a5841c945e85c2ac01b08a30b745f68ae6beb190333ce9d492eb0321c76cb7c173e",
            "a2bbdde4424ad59177f6697e4fb6ee812dfc02a6a6c4c3e3e2acf4c160ade723bc524047caa6e1b863ccdd104d679e18",
        ],
    },
    Fingerprint {
        version: 14,
        canonical: "5437342dabc2acffc42b49934b6a185fcb2eb39eb70275879a5841281fd05ab666e1bce753549117bd0975784ad911f5",
        predecessors: &[
            "973447dabcfac9972dc1b7acc762c4486dfbc79e090d49d2cfab85745cb41e7b0f3e556072c1f5b0f3faa03bbf45668e",
            "1a3822722e1db0416fe090c4e9d9c06b0145a1b3087ab40bf9b6e8a91b521af32ff9f8c73695bc1f523f04385497f662",
        ],
    },
    Fingerprint {
        version: 15,
        canonical: "bf8bc48afb403c09c8d3e288a67ba9416f96d7df85c77f3773f136a31535302b5d260e5073e2b03f20923d832df04545",
        predecessors: &[
            "bf8bc48afb403c09c8d3e288a67ba9416f96d7df85c77f3773f136a31535302b5d260e5073e2b03f20923d832df04545",
            "090af8a243dfdf3a005f56cc34edd1256f647a12b83f5943227100f05afdf3f76fc014f8cf197cdc68f497d35dd2ffb6",
        ],
    },
    Fingerprint {
        version: 16,
        canonical: "13b3776257e0c588246b4d29bd90a20830c90e35ce417cce489e1a12b978fde1770e540cb0ca24b9183e2e91131d3d62",
        predecessors: &[
            "13b3776257e0c588246b4d29bd90a20830c90e35ce417cce489e1a12b978fde1770e540cb0ca24b9183e2e91131d3d62",
            "9d018740b132d13110a34f9397adfb873c5a43f0bd70d39756272242f7cfb6d9e129adc0bbe3507b8b3424e1d3e36b1e",
        ],
    },
    Fingerprint {
        version: 17,
        canonical: "213dc588d168d053605919da94a1ccf5c8cc2e9f580045aac22ba345dd3238013b44789eb14004f5276463e6acab53b2",
        predecessors: &[
            "213dc588d168d053605919da94a1ccf5c8cc2e9f580045aac22ba345dd3238013b44789eb14004f5276463e6acab53b2",
            "2d33b76d3bde1d699ff47806ee808d30023943212ab321d022608553ddfaf67040a0b5fedeca008b18d01ca3270cfb6d",
        ],
    },
    Fingerprint {
        version: 18,
        canonical: "93fe4287c235c25121ff1e01df4ed7c745fb87db95c28d50ba3ba24e0b5475106a82f5939250b4de0aff3253be16e45a",
        predecessors: &[
            "93fe4287c235c25121ff1e01df4ed7c745fb87db95c28d50ba3ba24e0b5475106a82f5939250b4de0aff3253be16e45a",
            "9b0887f914e7c985c99d5802899589471a0997ca264219774ff5ffa13562c79ba83e3d24654c944c77dd7f1fd6750327",
        ],
    },
    Fingerprint {
        version: 19,
        canonical: "8743da75c440ab45473e19cf4b42b048f1d81a5737944ee3b9b9dddbfa376ce25bc7110b859ca06d439db22288049aa5",
        predecessors: &[
            "8743da75c440ab45473e19cf4b42b048f1d81a5737944ee3b9b9dddbfa376ce25bc7110b859ca06d439db22288049aa5",
            "5587118263f962c06e5c72a53c8ad87321914679b6b1d9d87c17ea0c0d6c85a69e500decb09358549aefe6aba667a292",
        ],
    },
];
