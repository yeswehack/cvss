CVSS
====

[![Latest Stable Version](https://poser.pugx.org/ywh/cvss/version)](https://packagist.org/packages/ywh/cvss)
[![Total Downloads](https://poser.pugx.org/ywh/cvss/downloads)](https://packagist.org/packages/ywh/cvss)
[![Latest Unstable Version](https://poser.pugx.org/ywh/cvss/v/unstable)](//packagist.org/packages/ywh/cvss)
[![License](https://poser.pugx.org/ywh/cvss/license)](https://packagist.org/packages/ywh/cvss)

Common Vulnerability Scoring System (CVSS) provides a robust and useful scoring system for IT vulnerabilities.

See https://www.first.org/cvss for more informations.


Documentation
=============

## 1 - Installation

Dowload the CVSS library using composer:

```php
composer require ywh/cvss
```

## 2 - Usage

### 2.1 Vector parser

First, you need to give the CVSSv3 calculator a valid CVSS vector:

```php
use YWH\Cvss;

$cvss = new Cvss3();
$cvss->setVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
```

Base metrics (AV,AC,PR,UI,S,C,I and A) must be defined.

An undefined metric will throw the following error:
```php
Symfony\Component\OptionsResolver\Exception\UndefinedOptionsException
```

A missing metric will throw the following error:
```php
Symfony\Component\OptionsResolver\Exception\MissingOptionsException
```

A wrong metric value will throw the following error:
```php
Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
```

Once the vector is valid, you will able to get several informations about the vector.

### 2.1 Scores

Score is float number from 0 to 10.
CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N vector has a 2.7 base score.

#### 2.1.1 Base score

```php
use YWH\Cvss;

$cvss = new Cvss3();
$cvss->setVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');

echo 'Base score: ' $cvss->getBaseScore();
// Base score: 0
```

### 2.1.2 Temporal score

```php
use YWH\Cvss;

$cvss = new Cvss3();
$cvss->setVector('CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N/E:U/RL:T/RC:C');

echo 'Base score: ' $cvss->getBaseScore();
// Base score: 2.7
echo 'Temporal score: ' $cvss->getTemporalScore();
// Temporal score: 2.4
```

### 2.1.2 Environmental score

```php
use YWH\Cvss;

$cvss = new Cvss3();
$cvss->setVector('CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:H/IR:M/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:U/MC:H/MI:N/MA:L');

echo 'Base score: ' $cvss->getBaseScore();
// Base score: 9.1
echo 'Temporal score: ' $cvss->getTemporalScore();
// Temporal score: 7.4
echo 'Environmental score: ' $cvss->getEnvironmentalScore();
// Environmental score: 7.4
```

### 2.2 Qualitative Severity Rating Scale

All score can be mapped to a qualitative rating, defined in the table bellow:

| Value | Textual representation | CVSS Score |
| :---: | ---------------------- | ---------- |
| N | None | 0.0 |
| L | Low | 0.1 - 3.9 |
| M | Medium | 4.0 - 6.9 |
| H | High | 7.0 - 8.9 |
| C | Critical | 9.0 - 10.0 |

