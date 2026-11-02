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
| `models.json` | **706 models** across **24 manufacturers**, with category, release year, EN + DE descriptions and matching keys |
| `categories.json` | **9 device categories** with EN + DE descriptions, each naming its icon |
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

## Images: linked, never hosted

This repository ships **neutral category icons only** — one per device type,
referenced from `categories.json`, drawn from au2mator's own icon set and
free for you to reuse. It deliberately contains **no manufacturer product
photos**.

Product photography is copyrighted by the manufacturer, and no reseller or
syndication licence covers redistributing it through a public repository.
We asked. The answer was no, consistently, across every source we checked.

What the data does carry is a **link** to the manufacturer's own image, on
the manufacturer's own server:

```json
"image_url": "https://cdsassets.apple.com/live/7WUAS350/images/iphone/2022-spring-iphone13-colors.png",
"image_source": "https://support.apple.com/en-us/108044",
"image_checked": "2026-11-02"
```

- `image_url` — the image file, always on an official manufacturer domain
- `image_source` — the official page the link was taken from, so anyone can
  verify the origin instead of trusting it
- `image_checked` — when the link was last confirmed to resolve

The same three fields exist on each **manufacturer**, pointing at that
company's own logo on its own website.

A model carries **either its correct own image or none at all**. Models
without an image simply have no image fields. Falling back to a category
icon is a presentation decision, handled by au2mator Asset Management
itself — it is deliberately not baked into this data.

Nothing is copied by this repository. If an import tool fetches an image, it
does so on the operator's instruction and stores it in that operator's own
installation.

### Rules for image links

1. **Official manufacturer domains only.** Not reseller shops, not blogs, not
   image databases, not scraped mirrors.
2. **`image_source` is mandatory** alongside `image_url`, and must be a page
   on the same manufacturer's official site.
3. **No image files in pull requests.** Links only. Manufacturer product
   images committed to this repository cannot be merged.

Current coverage: **Apple, 68 of 68 models**, linked to Apple's own support
CDN and sourced from Apple's four "Identify your ..." pages. Other
manufacturers have no model images yet.

**Manufacturer logos: 15 of 24**, each taken from that manufacturer's own
site. The remaining nine are deliberately empty rather than wrong: some
sites expose nothing better than a 32×32 `favicon.ico`, some block automated
access, and for sub-brands the only logo on offer belonged to the parent
company. A missing logo renders as the category icon, which beats showing
the wrong brand.

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
- **Image links** for manufacturers not covered yet — following the three
  rules above

Please keep the existing JSON structure and field names, and keep files
UTF-8 encoded.

### Known gaps

- `categories.json` defines `Printer` and `Monitor`, but `models.json`
  has no models in those categories yet
- `models.json` uses a `Server` category that is not yet described in
  `categories.json`
- Coverage is strongest where our own imports ran — notebooks and
  smartphones are well populated, peripherals barely
- Image links currently exist for Apple only; every other manufacturer has
  no image yet, which the portal renders as its category icon

## Status

The import scripts themselves are not published here yet. This repository
currently provides the master data they consume. If you are building your
own import against the au2mator ITAM API, this data is usable as-is.

## Licence

[MIT](LICENSE).

[`NOTICE.md`](NOTICE.md) adds the clarifications the MIT text does not cover
on its own: an explicit grant of **EU database rights** over the data files
so you can extract and re-use them without ambiguity, confirmation that the
**category icons are au2mator's own work** and need no third-party
attribution, confirmation that **manufacturer images linked via `image_url`
are not licensed here** and are never hosted in this repository, and the note
that contributions are accepted under the same licence.

---

Maintained by [au2mator](https://au2mator.com). Questions about the product:
<https://au2mator.com/asset-management/>
