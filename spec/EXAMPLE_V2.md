# Example Case v2

`tests/vectors/example_v2.hex` is the canonical SP-DIFFER case-format v2 example.

It is a composite example built from the pinned official BIP 352 snapshot and demonstrates the major v2 additions without using the largest official counts.

## High-Level Decode

- version: `2`
- seed: `0x52`
- flags: `0x000001fa`
- input_count: `1`
- recipient_group_count: `2`
- scan_output_count: `1`
- label_count: `2`

Flag decode:

- bit 1: input private keys present
- bit 3: previous-output `scriptPubKey` present
- bit 4: `scriptSig` present
- bit 5: `txinwitness` present
- bit 6: recipient groups present
- bit 7: outputs-to-scan present
- bit 8: receiver key material present

## Input

- type: `0x04` (`P2PKH`)
- outpoint vout: `1`
- previous-output `scriptPubKey`: `76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac`
- `scriptSig` length: `107`
- `txinwitness` length: `0`

## Recipient Groups

1. scan `0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4`
   spend `025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36`
   count `1`
2. scan `0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4`
   spend `03a6739499dc667d308baefea4de0c4a85cc72aece181bc05712d3919662610ff1`
   count `2`

## Receiver Section

- outputs_to_scan[0]: `d014d4860f67d607d60b1af70e0ee236b99658b61bb769832acbbe87c374439a`
- scan_privkey: `0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c`
- spend_privkey: `9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3`
- labels: `2`, `1001337`

## Purpose

This example is for parser and tooling validation. It is runnable through the compiled semantic runner and CLI surfaces that execute v2 cases through the semantic bridge and semantic worker ABI.
