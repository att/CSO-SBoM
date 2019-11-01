## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

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
  * [1.3 Collective Code Construction Contract](#13-collective-code-construction-contract)
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
* [6. Examples](#6-examples)
  * [6.1 Pull CloudPassage](#61-pull-cloudpassage)
  * [6.2 One day pyt into GraphDB](#62-one-day-pyt-into-graphdb)
  * [6.3 Make an image](#6.3-make-an-image)
  * [6.4 Query one day](#6.4-query-one-day)
  * [6.5 Query to compare two days](#6.5-query-to-compare-two-days)
  * [6.6 Histogram across known dates](#6.6-histogram-across-known-dates)
* [7. Examples](#7-day-in-the-life-of-cyber-security-evangelist)

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
* Tony Librera https://github.com/tlibrera1

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
* set shell env variables:
  * export CLOUDPASSAGEDICT='{ "groupname1" : ("ignore", "keyname", "keyvalue"), ..., "lastgrp" : ("mycomment", "02468ace", "13579bdf02468ace13579bdf02468ace") }'
  * export DATAPATH='path to directory to put pyt data'
* python3 sbom.py
* verify $DATAPATH/svr.2019.04.01.pyt was created and is non-zero.
  * But with today's date replacing 2019.04.01.
  * Note UTC is used for determining "today"
    * (so it might be tomorrow or yesterday depending on your timezone).
* for a more detailed view of the code traversed, see [pull_sbom.md](./Docs/pull_sbom.md)

## 6.2 One day pyt into GraphDB
* set shell env variables:
  * export DATAPATH='path to directory to get pyt data'
  * export  GDBPATH='path to directory to put gdb file'
* python3 make_gdb.py 2019.04.01 ##replacing date of pyt file to create graphdb for
* verify GraphDB/2019.04.01.gdb (but with today's date replacing 2019.04.01) was created and is non-zero.

## 6.3 Make an image
### 6.3.1 CVE/packages/servers
* given a cve show affected packages on affected servers
### 6.3.2 servers over time by groups
* given a list of dates, show how many servers in each group in stacked bar graph
* python3 queryn.numsvrs.py
* prerequisites:
  - export GDBPATH='path to directory of GraphDb files'
  - export ANLPATH='path to directory to put image and data'
  - export DATELIST='["date1", "date2", ...]


## 6.4 Query one day
### 6.4.1 list server by group
* python3 query1_svr_list.py {date}
  - where {date} is date to one you want to query eg '2019.04.01'
  - prerequisites:
    * export GDBPATH='path to directory of GraphDb files'
  - returns a print of a python dictionary with key=group, value=serverlist
### 6.4.2 server info
* python3 query1_svr.py {date} {server}
    - where {date} is date to one you want to query eg '2019.04.01'
    - where {server} is server by how cloudpassage id's eg '84a421cd887f11e887244dfe08192208'
    - prerequisites:
      * export GDBPATH='path to directory of GraphDb files'
* this returns a printout of information:
    * filename of gdb file
    * server ID (as cloudpassage know it)
    * server name
    * group server is member of
    * server hostname
    * Number of package/versions
    * Number of packages
      * note (package/versions minus packages) is the number 'extra' versions eg 775 package/versions minus 767 packages means there are 8 'extra' versions. This may be one package with 8 versions or 8 packages with two versions or anything inbetween
    * A list of the packages with multiple versions
    * A list of the supressed CVE's with their CVSS scores, sorted  CVSS/Hi-Lo
    * The number of packages with no CVE's
    * the number of packages with cve of cvss=10
    * a list of the packages from previous bullet
    * the number of packages with cve of cvss <10 & >=7
    * a list of the packages from previous bullet
    * the number of packages with cve of cvss <7 & >=5
    * the number of packages with cve of cvss <5 & >=0

### 6.4.3 multiversion
* python3 query1_multiver.py {date}
    - where {date} is date to one you want to query eg '2019.04.01'
    - prerequisites:
      * export GDBPATH='path to directory of GraphDb files'

* this returns a printout of information:
    * the number of servers with no multiver pakages
    * the number of servers with at least one multi-ver-package
    * bucket by how many extra packages-versions each server has:
      * 6 servers has 0 extra package-versions
      * 4 servers has 4 extra package-versions
      * ...
      * 1 servers has 31 extra package-versions
    * bucket by how many packages have extra versions each server has. Subtle difference from previous. For example second bullet below is same 4 servers as second bullet in previous section. What it means is there is one package with 5 version - ie all 4 extra package-verions are for the same package.
      * 6 servers has 0 mult-ver packages
      * 4 servers has 1 mult-ver packages
      * ...
      * 1 servers has 28 mult-ver packages
    * list the servers with zero extra package-versions
    * List the number of servers with a particular set of extra versions for a package. eg:
      * (4, "bash.x86_64/[':4.1.2-41.el6_8', ':4.1.2-48.el6']")
      * (1, "perl-Pod-Simple.x86_64/[':1:3.13-141.el6_7.1', ':1:3.13-144.el6']")
      * meaning 4 servers have 4.1.2-41.el6_8 and 4.1.2-48.el6 versions of bash.x86_64; and 1 server has 1:3.13-141.el6_7.1 and 1:3.13-144.el6 versions of perl-Pod-Simple.x86_64 package

### 6.4.4 Bin Server Counts by CVSS score of CVE present
For a given day, count and bin the cve's.
* python3 query1_cve_bin.py {date}
    - where {date} is date to one you want to query eg '2019.04.01'
    - prerequisites:
      * export GDBPATH='path to directory of GraphDb files'

### 6.4.5 fill in rest
* number servers
* stacked bar chart by group
* number packages
* number CVE's
* number CVE's > CVSS=N
* number servers with CVE of CVSS >N
* number supressed CVE's
* number servers with supressed CVE's
* number servers with supressed CVE of CVSS >N

## 6.5 Query to compare two days
* number servers
* stacked bar chart by group
* number packages
* number CVE's
* number CVE's > CVSS=N
* number servers with CVE of CVSS >N
* number supressed CVE's
* number servers with supressed CVE's
* number servers with supressed CVE of CVSS >N

## 6.6 Histogram across known dates
## 6.6.1 Histogram of number of servers(by group) over time
* python3 queryn_numsvrs.py outfile
## 6.6.2 Histogram of number of extra versions over time
* python3 queryn_multiver.py outfile
## 6.6.3 Histogram of number of servers with supressed cve's over time
* python3 queryn_sup_cve.py outfile
## 6.6.4 Histogram of number of attack points over time
* python3 queryn_cve_bin.py outfile
## 6.6.5 list dates of raw data and of graphdb
* python3 queryn_dates.py
## 6.6.n
* number packages
* number CVE's
* number CVE's > CVSS=N
* number servers with CVE of CVSS >N
* number supressed CVE's
* number servers with supressed CVE's
* number servers with supressed CVE of CVSS >N
# 7. Day in the life of cyber security evangelist
1. check what dates have data
  * python3 queryn_dates.py
2. if any dates have data but not gdb, process them
  * python3 make_gdb.py 2019.04.01 ##replacing unprocessed date
3 if today missing data and it is desired, then get it
  * python3 sbom.py
  * python3 make_gdb.py 2019.04.01 ##replacing date with today's
4. check state of vulnerabilities
  * ignoring suppressed and clutter for now (query displays with supr and clutter)
  * python3 query1_filt_cve.py 2019.04.01 ##replacing date with today's or whatever
5. look at some of random Servers
  * python3 query1_svr.py 2019.04.01 id_of_svr
