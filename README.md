# **Security Log Analyzer**

## **Review**

The project is based on information from the Nextwork website. The main objective of the project is to analyze security logs containing brute force attacks and generate a threat report in JSON format.

## **Features**

* The project contains an example SSH authentication log
* It uses Regex to extract the necessary fields (structured data) from the security log.
* An attack detection logic based on a threshold value has been created
* The analyzer classifies threats by severity
* A threat report is generated in JSON format, containing tagged IP addresses, the number of attempts, the names of target users, and severity levels.

## **Technologies**

Python

Regex

JSON

Git

Github

## **Project**

* structure analyzer.py - log analysis and brute force attack detection logic
* sample_auth.log - an example of an SSH authentication log file
* threat_report.json report in JSON format

## **Project objectives**

* Initial introduction to cybersecurity capabilities
* Working with authentication logs
* Detecting strange user activity when logging in
* Gaining experience in Python development
* Using git and github for version control

