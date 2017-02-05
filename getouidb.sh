#!/bin/bash
curl --location --create-dirs -o db/oui24.csv https://standards.ieee.org/develop/regauth/oui/oui.csv
curl --location --create-dirs -o db/oui28.csv https://standards.ieee.org/develop/regauth/oui28/mam.csv
curl --location --create-dirs -o db/oui36.csv https://standards.ieee.org/develop/regauth/oui36/oui36.csv
