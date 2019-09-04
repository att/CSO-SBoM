## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

To Do List:
* do each of these or make issue for each
* issues in 3
* make an issue for each of 4.n,5



# Astra-SBoM
Routines to assist in creating and using Software Bill of Materials for Astra.
This is a work in progress and probably
not ready to be much use to others as yet, but hopefully will be soon.
If you'd like to help, read
[1.3 Collective Code Construction Contract](#13-collective-code-constru
ction-contract).
For license info see [LICENSE](./LICENSE).

# Contents
* [1 Ground Rules](#1-ground-rules)
  * [1.1 License](#11-license)
  * [1.2 Code of Conduct](#12-code-of-conduct)
  * [1.3 Collective Code Construction Contract](#13-collective-code-constru
ction-contract)
  * [1.4 Style Guide](#14-style-guide)
  * [1.5 Maintainers](#15-maintainers)
* [2. The case for Software Bill of Materials](#2-the-case-for-software-bill-of-materials)
* [3. Vision/Reality](#3-vision-reality)
  * [3.1 Vision](#31-vision)
    * [3.1.1 Phase 1](#311-phase-1)
    * [3.1.2 Phase 2](#312-phase-2)
    * [3.1.3 Phase 3](#313-phase-3)
  * [3.2 Where we are today](#32-where-we-are-today)
* [4. Getting it running](#4-getting-it-running)
  * [4.1 Requirements](#41-requirements)
  * [4.2 Recommended modules](#42-recommended-modules)
  * [4.3 Installation](#43-installation)
  * [4.4 Configuration](#44-configuration)
  * [4.5 Operation](#45-operation)
  * [4.6 Troubleshooting & FAQ](#46-troubleshooting--faq)
* [5. Architecture and Design](#5-architecture-and-design)
  * [5.1 Software Architecture](#51-software-architecture)
  * [5.2 Design](#52-design)
  * [5.3 Design Decisions](#53-design-decisions)
  * [5.4 SBoM of the SBoM Software](#54-sbom-of-the-sbom-software)
* [6.Examples](#6-examples)
  * [6.1 Pull CloudPassage](#61-pull-cloudpassage)
  * [6.2 One day pyt into GraphDB](#62-one-day-pyt-into-graphdb)

# 1. Ground Rules
This section contains the basics on using and contributing to this project.

## 1.1 License
MIT License. See [LICENSE](./LICENSE).

## 1.2 Code of Conduct
TL;DR - Don't be a jerk!

To ensure that there are no barriers for any developers
who would like to get involved,
a [Code of Conduct](./Docs/code_of_conduct.md) was adopted.
Please read and adhere to it.

## 1.3 Collective Code Construction Contract
The [Astra-SBoM Collective Code Construction Contract](./Docs/collective_code_construction_contract.md)
(C4) provides a standard process for contributing, evaluating and discussing improvements on this software project.
It defines specific SDLC requirements
like a style guide, unit tests, git, etc.
It also establishes different personas,
with clear and distinct duties.
The C4 specifies the process for documenting
and discussing issues including seeking consensus and clear descriptions,
use of "pull requests" and systematic reviews.
Please read and adhere to it.

## 1.4 Style Guide
blah blah
See [Style Guide](./Docs/style_guide.md).

## 1.5 Maintainers
This repo is maintained by:
* Duncan Sparrell https://github.com/sparrell
* What is Tony's github id?

# 2. The case for Software Bill of Materials
fill in from ntia and blog


# 3. Vision / Reality

## 3.1 Vision

## 3.2 Where we are today

# 4. Getting it running

## 4.1 Requirements

## 4.2 Recommended modules

## 4.3 Installation

## 4.4 Configuration

## 4.5 Operation

## 4.6 Troubleshooting & FAQ

# 5. Architecture and Design

## 5.1 Software Architecture

## 5.2 Design

## 5.3 Design Decisions
[Design Decisions](./Docs/design_decisions.md) documents decision decisions made along the way.

## 5.4 SBoM of the SBoM Software
* a bunch of independent python modules
* list what dependencies in python
* make actual sbom files

# 6. Examples

## 6.1 Pull CloudPassage
* set shell env variable with Cloud Passage API keys e.g.
  * export CLOUDPASSAGEDICT='{ "group1" : ("what", "key1", "000..0"), ..., "groupN" : ("what", "keyN", "000..0") }'
* pythonw sbom.py
* verify Data/svr.2019.04.01.pyt was created and is non-zero. But with today's date replacing 2019.04.01. Note UTC is used for determining "today" (so it might be tomorrow or yesterday depending on your timezone).
* for a more detailed view of the code traversed, see [pull_sbom.md](./Docs/pull_sbom.md)

## 6.2 One day pyt into GraphDB
* pythonw make_gdb.py 2019.04.01 ##replacing date of pyt file to create graphdb for
* verify GraphDB/2019.04.01.gdb (but with today's date replacing 2019.04.01) was created and is non-zero.

## 6.3
