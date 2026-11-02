# au2mator Asset Management — Import Data

Open master data for importing hardware assets into
**[au2mator Asset Management](https://au2mator.com/asset-management/)**.

When you import devices from Intune, SCCM or a similar source, you normally
get a serial number, a user and a raw model string such as
`LIFEBOOK U7613` or `iPhone 15 Pro Max`. What you do not get is a tidy
catalogue: proper manufacturer names, a sensible category per device, a
readable model description.

That catalogue lives here. It is free, public, and meant to be improved by
the people using it.

## What au2mator Asset Management is

Asset management your whole organisation can actually use — not an
enterprise CMDB project. It sits **on top of** your existing MDM instead of
replacing it: no discovery, no agents, nothing installed on endpoints.

Highlights: warranty overview and planning, hardware chargeback with
auditable billing records, delegated and scoped asset administration, and
asset fields usable in every self-service form you build.

→ **<https://au2mator.com/asset-management/>**

## What is in this repository

| File | Content |
|---|---|
| `models.json` | **714 models** across **24 manufacturers**, with category, release year, EN + DE descriptions and matching keys |
| `categories.json` | **9 device categories** with EN + DE descriptions |
| `icons/` | **9 neutral category icons** (PNG) |

### `models.json`

Structured as manufacturer → category → models:

```json
{
  "model_name": "iPhone 15 Pro Max",
  "key_model_intune": "iPhone 15 Pro Max",
  "key_model_apple": "MU773ZD/A",
  "key_model_sccm": "",
  "model_number": "MQ9Y3NF/A",
  "release_year": "2023",
  "Description_EN": "Apple iPhone 15 Pro Max with A17 Pro chip, ...",
  "Description_DE": "Apple iPhone 15 Pro Max mit A17 Pro Chip, ..."
}
```

The `key_model_*` fields are the important part. Every source system reports
hardware differently — Intune, SCCM, Apple order codes, or whatever your
environment uses. Each key column maps one of those raw strings to the same
canonical model, so a device can be matched no matter where it came from.
`key_model_custom1` to `custom3` are free for your own sources.

Manufacturers currently covered: Apple, Dell, HP, HPE, Lenovo, Fujitsu,
Samsung, Microsoft, ASUS, Acer, MSI, Gigabyte, Dynabook, Alienware, Intel,
ZOTAC, MINIX, VMware, Zebra, Honeywell, KEYENCE, Poly, Yealink, step.

## About the icons

This repository ships **neutral category icons only** — one per device type.
It deliberately contains **no manufacturer product photos**.

Product photography is copyrighted by the manufacturer, and no reseller or
syndication licence covers redistributing it through a public repository.
We asked. The answer was no, consistently, across every source we checked.

A neutral set also looks better in practice: a catalogue that shows a glossy
photo for one brand and a blank placeholder for the next is worse than one
that is consistently clean.

**Please do not submit manufacturer product images in a pull request** —
they cannot be merged.

## Contributing

Missing a model? A wrong category, a typo, a device your Intune tenant
reports under a different string? Pull requests are welcome — this data gets
better the more environments it meets.

Useful contributions:

- **New models**, with manufacturer, category and at least one `key_model_*`
  value
- **Additional matching keys** for models that already exist, when your
  source system reports them differently
- **Corrections** to categories, descriptions or release years
- **German descriptions** where only English exists, and vice versa

Please keep the existing JSON structure and field names, and keep files
UTF-8 encoded.

### Known gaps

- `categories.json` defines `Printer` and `Monitor`, but `models.json`
  has no models in those categories yet
- `models.json` uses a `Server` category that is not yet described in
  `categories.json`
- Coverage is strongest where our own imports ran — notebooks and
  smartphones are well populated, peripherals barely

## Status

The import scripts themselves are not published here yet. This repository
currently provides the master data they consume. If you are building your
own import against the au2mator ITAM API, this data is usable as-is.

---

Maintained by [au2mator](https://au2mator.com). Questions about the product:
<https://au2mator.com/asset-management/>
