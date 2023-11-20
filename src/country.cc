#include "country.hh"

#include <cctype>
#include <cstdlib>
#include <cstring>

#include "status.hh"
#include "str.hh"
#include "virtual_fs.hh"

namespace maf {

namespace iso3166 {

const Arr<Country, 249> kCountries = {
    Country{"Afghanistan", {'A', 'F'}, {'A', 'F', 'G'}, 4},
    {"Albania", {'A', 'L'}, {'A', 'L', 'B'}, 8},
    {"Algeria", {'D', 'Z'}, {'D', 'Z', 'A'}, 12},
    {"American Samoa", {'A', 'S'}, {'A', 'S', 'M'}, 16},
    {"Andorra", {'A', 'D'}, {'A', 'N', 'D'}, 20},
    {"Angola", {'A', 'O'}, {'A', 'G', 'O'}, 24},
    {"Anguilla", {'A', 'I'}, {'A', 'I', 'A'}, 660},
    {"Antarctica", {'A', 'Q'}, {'A', 'T', 'A'}, 10},
    {"Antigua and Barbuda", {'A', 'G'}, {'A', 'T', 'G'}, 28},
    {"Argentina", {'A', 'R'}, {'A', 'R', 'G'}, 32},
    {"Armenia", {'A', 'M'}, {'A', 'R', 'M'}, 51},
    {"Aruba", {'A', 'W'}, {'A', 'B', 'W'}, 533},
    {"Australia", {'A', 'U'}, {'A', 'U', 'S'}, 36},
    {"Austria", {'A', 'T'}, {'A', 'U', 'T'}, 40},
    {"Azerbaijan", {'A', 'Z'}, {'A', 'Z', 'E'}, 31},
    {"Bahamas (the)", {'B', 'S'}, {'B', 'H', 'S'}, 44},
    {"Bahrain", {'B', 'H'}, {'B', 'H', 'R'}, 48},
    {"Bangladesh", {'B', 'D'}, {'B', 'G', 'D'}, 50},
    {"Barbados", {'B', 'B'}, {'B', 'R', 'B'}, 52},
    {"Belarus", {'B', 'Y'}, {'B', 'L', 'R'}, 112},
    {"Belgium", {'B', 'E'}, {'B', 'E', 'L'}, 56},
    {"Belize", {'B', 'Z'}, {'B', 'L', 'Z'}, 84},
    {"Benin", {'B', 'J'}, {'B', 'E', 'N'}, 204},
    {"Bermuda", {'B', 'M'}, {'B', 'M', 'U'}, 60},
    {"Bhutan", {'B', 'T'}, {'B', 'T', 'N'}, 64},
    {"Bolivia (Plurinational State of)", {'B', 'O'}, {'B', 'O', 'L'}, 68},
    {"Bonaire, Sint Eustatius and Saba", {'B', 'Q'}, {'B', 'E', 'S'}, 535},
    {"Bosnia and Herzegovina", {'B', 'A'}, {'B', 'I', 'H'}, 70},
    {"Botswana", {'B', 'W'}, {'B', 'W', 'A'}, 72},
    {"Bouvet Island", {'B', 'V'}, {'B', 'V', 'T'}, 74},
    {"Brazil", {'B', 'R'}, {'B', 'R', 'A'}, 76},
    {"British Indian Ocean Territory (the)", {'I', 'O'}, {'I', 'O', 'T'}, 86},
    {"Brunei Darussalam", {'B', 'N'}, {'B', 'R', 'N'}, 96},
    {"Bulgaria", {'B', 'G'}, {'B', 'G', 'R'}, 100},
    {"Burkina Faso", {'B', 'F'}, {'B', 'F', 'A'}, 854},
    {"Burundi", {'B', 'I'}, {'B', 'D', 'I'}, 108},
    {"Cabo Verde", {'C', 'V'}, {'C', 'P', 'V'}, 132},
    {"Cambodia", {'K', 'H'}, {'K', 'H', 'M'}, 116},
    {"Cameroon", {'C', 'M'}, {'C', 'M', 'R'}, 120},
    {"Canada", {'C', 'A'}, {'C', 'A', 'N'}, 124},
    {"Cayman Islands (the)", {'K', 'Y'}, {'C', 'Y', 'M'}, 136},
    {"Central African Republic (the)", {'C', 'F'}, {'C', 'A', 'F'}, 140},
    {"Chad", {'T', 'D'}, {'T', 'C', 'D'}, 148},
    {"Chile", {'C', 'L'}, {'C', 'H', 'L'}, 152},
    {"China", {'C', 'N'}, {'C', 'H', 'N'}, 156},
    {"Christmas Island", {'C', 'X'}, {'C', 'X', 'R'}, 162},
    {"Cocos (Keeling) Islands (the)", {'C', 'C'}, {'C', 'C', 'K'}, 166},
    {"Colombia", {'C', 'O'}, {'C', 'O', 'L'}, 170},
    {"Comoros (the)", {'K', 'M'}, {'C', 'O', 'M'}, 174},
    {"Congo (the Democratic Republic of the)",
     {'C', 'D'},
     {'C', 'O', 'D'},
     180},
    {"Congo (the)", {'C', 'G'}, {'C', 'O', 'G'}, 178},
    {"Cook Islands (the)", {'C', 'K'}, {'C', 'O', 'K'}, 184},
    {"Costa Rica", {'C', 'R'}, {'C', 'R', 'I'}, 188},
    {"Croatia", {'H', 'R'}, {'H', 'R', 'V'}, 191},
    {"Cuba", {'C', 'U'}, {'C', 'U', 'B'}, 192},
    {"Curaçao", {'C', 'W'}, {'C', 'U', 'W'}, 531},
    {"Cyprus", {'C', 'Y'}, {'C', 'Y', 'P'}, 196},
    {"Czechia", {'C', 'Z'}, {'C', 'Z', 'E'}, 203},
    {"Côte d'Ivoire", {'C', 'I'}, {'C', 'I', 'V'}, 384},
    {"Denmark", {'D', 'K'}, {'D', 'N', 'K'}, 208},
    {"Djibouti", {'D', 'J'}, {'D', 'J', 'I'}, 262},
    {"Dominica", {'D', 'M'}, {'D', 'M', 'A'}, 212},
    {"Dominican Republic (the)", {'D', 'O'}, {'D', 'O', 'M'}, 214},
    {"Ecuador", {'E', 'C'}, {'E', 'C', 'U'}, 218},
    {"Egypt", {'E', 'G'}, {'E', 'G', 'Y'}, 818},
    {"El Salvador", {'S', 'V'}, {'S', 'L', 'V'}, 222},
    {"Equatorial Guinea", {'G', 'Q'}, {'G', 'N', 'Q'}, 226},
    {"Eritrea", {'E', 'R'}, {'E', 'R', 'I'}, 232},
    {"Estonia", {'E', 'E'}, {'E', 'S', 'T'}, 233},
    {"Eswatini", {'S', 'Z'}, {'S', 'W', 'Z'}, 748},
    {"Ethiopia", {'E', 'T'}, {'E', 'T', 'H'}, 231},
    {"Falkland Islands (the) [Malvinas]", {'F', 'K'}, {'F', 'L', 'K'}, 238},
    {"Faroe Islands (the)", {'F', 'O'}, {'F', 'R', 'O'}, 234},
    {"Fiji", {'F', 'J'}, {'F', 'J', 'I'}, 242},
    {"Finland", {'F', 'I'}, {'F', 'I', 'N'}, 246},
    {"France", {'F', 'R'}, {'F', 'R', 'A'}, 250},
    {"French Guiana", {'G', 'F'}, {'G', 'U', 'F'}, 254},
    {"French Polynesia", {'P', 'F'}, {'P', 'Y', 'F'}, 258},
    {"French Southern Territories (the)", {'T', 'F'}, {'A', 'T', 'F'}, 260},
    {"Gabon", {'G', 'A'}, {'G', 'A', 'B'}, 266},
    {"Gambia (the)", {'G', 'M'}, {'G', 'M', 'B'}, 270},
    {"Georgia", {'G', 'E'}, {'G', 'E', 'O'}, 268},
    {"Germany", {'D', 'E'}, {'D', 'E', 'U'}, 276},
    {"Ghana", {'G', 'H'}, {'G', 'H', 'A'}, 288},
    {"Gibraltar", {'G', 'I'}, {'G', 'I', 'B'}, 292},
    {"Greece", {'G', 'R'}, {'G', 'R', 'C'}, 300},
    {"Greenland", {'G', 'L'}, {'G', 'R', 'L'}, 304},
    {"Grenada", {'G', 'D'}, {'G', 'R', 'D'}, 308},
    {"Guadeloupe", {'G', 'P'}, {'G', 'L', 'P'}, 312},
    {"Guam", {'G', 'U'}, {'G', 'U', 'M'}, 316},
    {"Guatemala", {'G', 'T'}, {'G', 'T', 'M'}, 320},
    {"Guernsey", {'G', 'G'}, {'G', 'G', 'Y'}, 831},
    {"Guinea", {'G', 'N'}, {'G', 'I', 'N'}, 324},
    {"Guinea-Bissau", {'G', 'W'}, {'G', 'N', 'B'}, 624},
    {"Guyana", {'G', 'Y'}, {'G', 'U', 'Y'}, 328},
    {"Haiti", {'H', 'T'}, {'H', 'T', 'I'}, 332},
    {"Heard Island and McDonald Islands", {'H', 'M'}, {'H', 'M', 'D'}, 334},
    {"Holy See (the)", {'V', 'A'}, {'V', 'A', 'T'}, 336},
    {"Honduras", {'H', 'N'}, {'H', 'N', 'D'}, 340},
    {"Hong Kong", {'H', 'K'}, {'H', 'K', 'G'}, 344},
    {"Hungary", {'H', 'U'}, {'H', 'U', 'N'}, 348},
    {"Iceland", {'I', 'S'}, {'I', 'S', 'L'}, 352},
    {"India", {'I', 'N'}, {'I', 'N', 'D'}, 356},
    {"Indonesia", {'I', 'D'}, {'I', 'D', 'N'}, 360},
    {"Iran (Islamic Republic of)", {'I', 'R'}, {'I', 'R', 'N'}, 364},
    {"Iraq", {'I', 'Q'}, {'I', 'R', 'Q'}, 368},
    {"Ireland", {'I', 'E'}, {'I', 'R', 'L'}, 372},
    {"Isle of Man", {'I', 'M'}, {'I', 'M', 'N'}, 833},
    {"Israel", {'I', 'L'}, {'I', 'S', 'R'}, 376},
    {"Italy", {'I', 'T'}, {'I', 'T', 'A'}, 380},
    {"Jamaica", {'J', 'M'}, {'J', 'A', 'M'}, 388},
    {"Japan", {'J', 'P'}, {'J', 'P', 'N'}, 392},
    {"Jersey", {'J', 'E'}, {'J', 'E', 'Y'}, 832},
    {"Jordan", {'J', 'O'}, {'J', 'O', 'R'}, 400},
    {"Kazakhstan", {'K', 'Z'}, {'K', 'A', 'Z'}, 398},
    {"Kenya", {'K', 'E'}, {'K', 'E', 'N'}, 404},
    {"Kiribati", {'K', 'I'}, {'K', 'I', 'R'}, 296},
    {"Korea (the Democratic People's Republic of)",
     {'K', 'P'},
     {'P', 'R', 'K'},
     408},
    {"Korea (the Republic of)", {'K', 'R'}, {'K', 'O', 'R'}, 410},
    {"Kuwait", {'K', 'W'}, {'K', 'W', 'T'}, 414},
    {"Kyrgyzstan", {'K', 'G'}, {'K', 'G', 'Z'}, 417},
    {"Lao People's Democratic Republic (the)",
     {'L', 'A'},
     {'L', 'A', 'O'},
     418},
    {"Latvia", {'L', 'V'}, {'L', 'V', 'A'}, 428},
    {"Lebanon", {'L', 'B'}, {'L', 'B', 'N'}, 422},
    {"Lesotho", {'L', 'S'}, {'L', 'S', 'O'}, 426},
    {"Liberia", {'L', 'R'}, {'L', 'B', 'R'}, 430},
    {"Libya", {'L', 'Y'}, {'L', 'B', 'Y'}, 434},
    {"Liechtenstein", {'L', 'I'}, {'L', 'I', 'E'}, 438},
    {"Lithuania", {'L', 'T'}, {'L', 'T', 'U'}, 440},
    {"Luxembourg", {'L', 'U'}, {'L', 'U', 'X'}, 442},
    {"Macao", {'M', 'O'}, {'M', 'A', 'C'}, 446},
    {"Madagascar", {'M', 'G'}, {'M', 'D', 'G'}, 450},
    {"Malawi", {'M', 'W'}, {'M', 'W', 'I'}, 454},
    {"Malaysia", {'M', 'Y'}, {'M', 'Y', 'S'}, 458},
    {"Maldives", {'M', 'V'}, {'M', 'D', 'V'}, 462},
    {"Mali", {'M', 'L'}, {'M', 'L', 'I'}, 466},
    {"Malta", {'M', 'T'}, {'M', 'L', 'T'}, 470},
    {"Marshall Islands (the)", {'M', 'H'}, {'M', 'H', 'L'}, 584},
    {"Martinique", {'M', 'Q'}, {'M', 'T', 'Q'}, 474},
    {"Mauritania", {'M', 'R'}, {'M', 'R', 'T'}, 478},
    {"Mauritius", {'M', 'U'}, {'M', 'U', 'S'}, 480},
    {"Mayotte", {'Y', 'T'}, {'M', 'Y', 'T'}, 175},
    {"Mexico", {'M', 'X'}, {'M', 'E', 'X'}, 484},
    {"Micronesia (Federated States of)", {'F', 'M'}, {'F', 'S', 'M'}, 583},
    {"Moldova (the Republic of)", {'M', 'D'}, {'M', 'D', 'A'}, 498},
    {"Monaco", {'M', 'C'}, {'M', 'C', 'O'}, 492},
    {"Mongolia", {'M', 'N'}, {'M', 'N', 'G'}, 496},
    {"Montenegro", {'M', 'E'}, {'M', 'N', 'E'}, 499},
    {"Montserrat", {'M', 'S'}, {'M', 'S', 'R'}, 500},
    {"Morocco", {'M', 'A'}, {'M', 'A', 'R'}, 504},
    {"Mozambique", {'M', 'Z'}, {'M', 'O', 'Z'}, 508},
    {"Myanmar", {'M', 'M'}, {'M', 'M', 'R'}, 104},
    {"Namibia", {'N', 'A'}, {'N', 'A', 'M'}, 516},
    {"Nauru", {'N', 'R'}, {'N', 'R', 'U'}, 520},
    {"Nepal", {'N', 'P'}, {'N', 'P', 'L'}, 524},
    {"Netherlands (the)", {'N', 'L'}, {'N', 'L', 'D'}, 528},
    {"New Caledonia", {'N', 'C'}, {'N', 'C', 'L'}, 540},
    {"New Zealand", {'N', 'Z'}, {'N', 'Z', 'L'}, 554},
    {"Nicaragua", {'N', 'I'}, {'N', 'I', 'C'}, 558},
    {"Niger (the)", {'N', 'E'}, {'N', 'E', 'R'}, 562},
    {"Nigeria", {'N', 'G'}, {'N', 'G', 'A'}, 566},
    {"Niue", {'N', 'U'}, {'N', 'I', 'U'}, 570},
    {"Norfolk Island", {'N', 'F'}, {'N', 'F', 'K'}, 574},
    {"Northern Mariana Islands (the)", {'M', 'P'}, {'M', 'N', 'P'}, 580},
    {"Norway", {'N', 'O'}, {'N', 'O', 'R'}, 578},
    {"Oman", {'O', 'M'}, {'O', 'M', 'N'}, 512},
    {"Pakistan", {'P', 'K'}, {'P', 'A', 'K'}, 586},
    {"Palau", {'P', 'W'}, {'P', 'L', 'W'}, 585},
    {"Palestine, State of", {'P', 'S'}, {'P', 'S', 'E'}, 275},
    {"Panama", {'P', 'A'}, {'P', 'A', 'N'}, 591},
    {"Papua New Guinea", {'P', 'G'}, {'P', 'N', 'G'}, 598},
    {"Paraguay", {'P', 'Y'}, {'P', 'R', 'Y'}, 600},
    {"Peru", {'P', 'E'}, {'P', 'E', 'R'}, 604},
    {"Philippines (the)", {'P', 'H'}, {'P', 'H', 'L'}, 608},
    {"Pitcairn", {'P', 'N'}, {'P', 'C', 'N'}, 612},
    {"Poland", {'P', 'L'}, {'P', 'O', 'L'}, 616},
    {"Portugal", {'P', 'T'}, {'P', 'R', 'T'}, 620},
    {"Puerto Rico", {'P', 'R'}, {'P', 'R', 'I'}, 630},
    {"Qatar", {'Q', 'A'}, {'Q', 'A', 'T'}, 634},
    {"Republic of North Macedonia", {'M', 'K'}, {'M', 'K', 'D'}, 807},
    {"Romania", {'R', 'O'}, {'R', 'O', 'U'}, 642},
    {"Russian Federation (the)", {'R', 'U'}, {'R', 'U', 'S'}, 643},
    {"Rwanda", {'R', 'W'}, {'R', 'W', 'A'}, 646},
    {"Réunion", {'R', 'E'}, {'R', 'E', 'U'}, 638},
    {"Saint Barthélemy", {'B', 'L'}, {'B', 'L', 'M'}, 652},
    {"Saint Helena, Ascension and Tristan da Cunha",
     {'S', 'H'},
     {'S', 'H', 'N'},
     654},
    {"Saint Kitts and Nevis", {'K', 'N'}, {'K', 'N', 'A'}, 659},
    {"Saint Lucia", {'L', 'C'}, {'L', 'C', 'A'}, 662},
    {"Saint Martin (French part)", {'M', 'F'}, {'M', 'A', 'F'}, 663},
    {"Saint Pierre and Miquelon", {'P', 'M'}, {'S', 'P', 'M'}, 666},
    {"Saint Vincent and the Grenadines", {'V', 'C'}, {'V', 'C', 'T'}, 670},
    {"Samoa", {'W', 'S'}, {'W', 'S', 'M'}, 882},
    {"San Marino", {'S', 'M'}, {'S', 'M', 'R'}, 674},
    {"Sao Tome and Principe", {'S', 'T'}, {'S', 'T', 'P'}, 678},
    {"Saudi Arabia", {'S', 'A'}, {'S', 'A', 'U'}, 682},
    {"Senegal", {'S', 'N'}, {'S', 'E', 'N'}, 686},
    {"Serbia", {'R', 'S'}, {'S', 'R', 'B'}, 688},
    {"Seychelles", {'S', 'C'}, {'S', 'Y', 'C'}, 690},
    {"Sierra Leone", {'S', 'L'}, {'S', 'L', 'E'}, 694},
    {"Singapore", {'S', 'G'}, {'S', 'G', 'P'}, 702},
    {"Sint Maarten (Dutch part)", {'S', 'X'}, {'S', 'X', 'M'}, 534},
    {"Slovakia", {'S', 'K'}, {'S', 'V', 'K'}, 703},
    {"Slovenia", {'S', 'I'}, {'S', 'V', 'N'}, 705},
    {"Solomon Islands", {'S', 'B'}, {'S', 'L', 'B'}, 90},
    {"Somalia", {'S', 'O'}, {'S', 'O', 'M'}, 706},
    {"South Africa", {'Z', 'A'}, {'Z', 'A', 'F'}, 710},
    {"South Georgia and the South Sandwich Islands",
     {'G', 'S'},
     {'S', 'G', 'S'},
     239},
    {"South Sudan", {'S', 'S'}, {'S', 'S', 'D'}, 728},
    {"Spain", {'E', 'S'}, {'E', 'S', 'P'}, 724},
    {"Sri Lanka", {'L', 'K'}, {'L', 'K', 'A'}, 144},
    {"Sudan (the)", {'S', 'D'}, {'S', 'D', 'N'}, 729},
    {"Suriname", {'S', 'R'}, {'S', 'U', 'R'}, 740},
    {"Svalbard and Jan Mayen", {'S', 'J'}, {'S', 'J', 'M'}, 744},
    {"Sweden", {'S', 'E'}, {'S', 'W', 'E'}, 752},
    {"Switzerland", {'C', 'H'}, {'C', 'H', 'E'}, 756},
    {"Syrian Arab Republic", {'S', 'Y'}, {'S', 'Y', 'R'}, 760},
    {"Taiwan (Province of China)", {'T', 'W'}, {'T', 'W', 'N'}, 158},
    {"Tajikistan", {'T', 'J'}, {'T', 'J', 'K'}, 762},
    {"Tanzania, United Republic of", {'T', 'Z'}, {'T', 'Z', 'A'}, 834},
    {"Thailand", {'T', 'H'}, {'T', 'H', 'A'}, 764},
    {"Timor-Leste", {'T', 'L'}, {'T', 'L', 'S'}, 626},
    {"Togo", {'T', 'G'}, {'T', 'G', 'O'}, 768},
    {"Tokelau", {'T', 'K'}, {'T', 'K', 'L'}, 772},
    {"Tonga", {'T', 'O'}, {'T', 'O', 'N'}, 776},
    {"Trinidad and Tobago", {'T', 'T'}, {'T', 'T', 'O'}, 780},
    {"Tunisia", {'T', 'N'}, {'T', 'U', 'N'}, 788},
    {"Turkey", {'T', 'R'}, {'T', 'U', 'R'}, 792},
    {"Turkmenistan", {'T', 'M'}, {'T', 'K', 'M'}, 795},
    {"Turks and Caicos Islands (the)", {'T', 'C'}, {'T', 'C', 'A'}, 796},
    {"Tuvalu", {'T', 'V'}, {'T', 'U', 'V'}, 798},
    {"Uganda", {'U', 'G'}, {'U', 'G', 'A'}, 800},
    {"Ukraine", {'U', 'A'}, {'U', 'K', 'R'}, 804},
    {"United Arab Emirates (the)", {'A', 'E'}, {'A', 'R', 'E'}, 784},
    {"United Kingdom of Great Britain and Northern Ireland (the)",
     {'G', 'B'},
     {'G', 'B', 'R'},
     826},
    {"United States Minor Outlying Islands (the)",
     {'U', 'M'},
     {'U', 'M', 'I'},
     581},
    {"United States of America (the)", {'U', 'S'}, {'U', 'S', 'A'}, 840},
    {"Uruguay", {'U', 'Y'}, {'U', 'R', 'Y'}, 858},
    {"Uzbekistan", {'U', 'Z'}, {'U', 'Z', 'B'}, 860},
    {"Vanuatu", {'V', 'U'}, {'V', 'U', 'T'}, 548},
    {"Venezuela (Bolivarian Republic of)", {'V', 'E'}, {'V', 'E', 'N'}, 862},
    {"Viet Nam", {'V', 'N'}, {'V', 'N', 'M'}, 704},
    {"Virgin Islands (British)", {'V', 'G'}, {'V', 'G', 'B'}, 92},
    {"Virgin Islands (U.S.)", {'V', 'I'}, {'V', 'I', 'R'}, 850},
    {"Wallis and Futuna", {'W', 'F'}, {'W', 'L', 'F'}, 876},
    {"Western Sahara", {'E', 'H'}, {'E', 'S', 'H'}, 732},
    {"Yemen", {'Y', 'E'}, {'Y', 'E', 'M'}, 887},
    {"Zambia", {'Z', 'M'}, {'Z', 'M', 'B'}, 894},
    {"Zimbabwe", {'Z', 'W'}, {'Z', 'W', 'E'}, 716},
    {"Åland Islands", {'A', 'X'}, {'A', 'L', 'A'}, 248},
};

namespace alpha2 {

const Country
    *AF = &kCountries[0],
    *AL = &kCountries[1], *DZ = &kCountries[2], *AS = &kCountries[3],
    *AD = &kCountries[4], *AO = &kCountries[5], *AI = &kCountries[6],
    *AQ = &kCountries[7], *AG = &kCountries[8], *AR = &kCountries[9],
    *AM = &kCountries[10], *AW = &kCountries[11], *AU = &kCountries[12],
    *AT = &kCountries[13], *AZ = &kCountries[14], *BS = &kCountries[15],
    *BH = &kCountries[16], *BD = &kCountries[17], *BB = &kCountries[18],
    *BY = &kCountries[19], *BE = &kCountries[20], *BZ = &kCountries[21],
    *BJ = &kCountries[22], *BM = &kCountries[23], *BT = &kCountries[24],
    *BO = &kCountries[25], *BQ = &kCountries[26], *BA = &kCountries[27],
    *BW = &kCountries[28], *BV = &kCountries[29], *BR = &kCountries[30],
    *IO = &kCountries[31], *BN = &kCountries[32], *BG = &kCountries[33],
    *BF = &kCountries[34], *BI = &kCountries[35], *CV = &kCountries[36],
    *KH = &kCountries[37], *CM = &kCountries[38], *CA = &kCountries[39],
    *KY = &kCountries[40], *CF = &kCountries[41], *TD = &kCountries[42],
    *CL = &kCountries[43], *CN = &kCountries[44], *CX = &kCountries[45],
    *CC = &kCountries[46], *CO = &kCountries[47], *KM = &kCountries[48],
    *CD = &kCountries[49], *CG = &kCountries[50], *CK = &kCountries[51],
    *CR = &kCountries[52], *HR = &kCountries[53], *CU = &kCountries[54],
    *CW = &kCountries[55], *CY = &kCountries[56], *CZ = &kCountries[57],
    *CI = &kCountries[58], *DK = &kCountries[59], *DJ = &kCountries[60],
    *DM = &kCountries[61], *DO = &kCountries[62], *EC = &kCountries[63],
    *EG = &kCountries[64], *SV = &kCountries[65], *GQ = &kCountries[66],
    *ER = &kCountries[67], *EE = &kCountries[68], *SZ = &kCountries[69],
    *ET = &kCountries[70], *FK = &kCountries[71], *FO = &kCountries[72],
    *FJ = &kCountries[73], *FI = &kCountries[74], *FR = &kCountries[75],
    *GF = &kCountries[76], *PF = &kCountries[77], *TF = &kCountries[78],
    *GA = &kCountries[79], *GM = &kCountries[80], *GE = &kCountries[81],
    *DE = &kCountries[82], *GH = &kCountries[83], *GI = &kCountries[84],
    *GR = &kCountries[85], *GL = &kCountries[86], *GD = &kCountries[87],
    *GP = &kCountries[88], *GU = &kCountries[89], *GT = &kCountries[90],
    *GG = &kCountries[91], *GN = &kCountries[92], *GW = &kCountries[93],
    *GY = &kCountries[94], *HT = &kCountries[95], *HM = &kCountries[96],
    *VA = &kCountries[97], *HN = &kCountries[98], *HK = &kCountries[99],
    *HU = &kCountries[100], *IS = &kCountries[101], *IN = &kCountries[102],
    *ID = &kCountries[103], *IR = &kCountries[104], *IQ = &kCountries[105],
    *IE = &kCountries[106], *IM = &kCountries[107], *IL = &kCountries[108],
    *IT = &kCountries[109], *JM = &kCountries[110], *JP = &kCountries[111],
    *JE = &kCountries[112], *JO = &kCountries[113], *KZ = &kCountries[114],
    *KE = &kCountries[115], *KI = &kCountries[116], *KP = &kCountries[117],
    *KR = &kCountries[118], *KW = &kCountries[119], *KG = &kCountries[120],
    *LA = &kCountries[121], *LV = &kCountries[122], *LB = &kCountries[123],
    *LS = &kCountries[124], *LR = &kCountries[125], *LY = &kCountries[126],
    *LI = &kCountries[127], *LT = &kCountries[128], *LU = &kCountries[129],
    *MO = &kCountries[130], *MG = &kCountries[131], *MW = &kCountries[132],
    *MY = &kCountries[133], *MV = &kCountries[134], *ML = &kCountries[135],
    *MT = &kCountries[136], *MH = &kCountries[137], *MQ = &kCountries[138],
    *MR = &kCountries[139], *MU = &kCountries[140], *YT = &kCountries[141],
    *MX = &kCountries[142], *FM = &kCountries[143], *MD = &kCountries[144],
    *MC = &kCountries[145], *MN = &kCountries[146], *ME = &kCountries[147],
    *MS = &kCountries[148], *MA = &kCountries[149], *MZ = &kCountries[150],
    *MM = &kCountries[151], *NA = &kCountries[152], *NR = &kCountries[153],
    *NP = &kCountries[154], *NL = &kCountries[155], *NC = &kCountries[156],
    *NZ = &kCountries[157], *NI = &kCountries[158], *NE = &kCountries[159],
    *NG = &kCountries[160], *NU = &kCountries[161], *NF = &kCountries[162],
    *MP = &kCountries[163], *NO = &kCountries[164], *OM = &kCountries[165],
    *PK = &kCountries[166], *PW = &kCountries[167], *PS = &kCountries[168],
    *PA = &kCountries[169], *PG = &kCountries[170], *PY = &kCountries[171],
    *PE = &kCountries[172], *PH = &kCountries[173], *PN = &kCountries[174],
    *PL = &kCountries[175], *PT = &kCountries[176], *PR = &kCountries[177],
    *QA = &kCountries[178], *MK = &kCountries[179], *RO = &kCountries[180],
    *RU = &kCountries[181], *RW = &kCountries[182], *RE = &kCountries[183],
    *BL = &kCountries[184], *SH = &kCountries[185], *KN = &kCountries[186],
    *LC = &kCountries[187], *MF = &kCountries[188], *PM = &kCountries[189],
    *VC = &kCountries[190], *WS = &kCountries[191], *SM = &kCountries[192],
    *ST = &kCountries[193], *SA = &kCountries[194], *SN = &kCountries[195],
    *RS = &kCountries[196], *SC = &kCountries[197], *SL = &kCountries[198],
    *SG = &kCountries[199], *SX = &kCountries[200], *SK = &kCountries[201],
    *SI = &kCountries[202], *SB = &kCountries[203], *SO = &kCountries[204],
    *ZA = &kCountries[205], *GS = &kCountries[206], *SS = &kCountries[207],
    *ES = &kCountries[208], *LK = &kCountries[209], *SD = &kCountries[210],
    *SR = &kCountries[211], *SJ = &kCountries[212], *SE = &kCountries[213],
    *CH = &kCountries[214], *SY = &kCountries[215], *TW = &kCountries[216],
    *TJ = &kCountries[217], *TZ = &kCountries[218], *TH = &kCountries[219],
    *TL = &kCountries[220], *TG = &kCountries[221], *TK = &kCountries[222],
    *TO = &kCountries[223], *TT = &kCountries[224], *TN = &kCountries[225],
    *TR = &kCountries[226], *TM = &kCountries[227], *TC = &kCountries[228],
    *TV = &kCountries[229], *UG = &kCountries[230], *UA = &kCountries[231],
    *AE = &kCountries[232], *GB = &kCountries[233], *UM = &kCountries[234],
    *US = &kCountries[235], *UY = &kCountries[236], *UZ = &kCountries[237],
    *VU = &kCountries[238], *VE = &kCountries[239], *VN = &kCountries[240],
    *VG = &kCountries[241], *VI = &kCountries[242], *WF = &kCountries[243],
    *EH = &kCountries[244], *YE = &kCountries[245], *ZM = &kCountries[246],
    *ZW = &kCountries[247], *AX = &kCountries[248];

} // namespace alpha2

} // namespace iso3166

using namespace iso3166;

static const Country *GetMachineCountryFromEnv() {
  if (char *var = getenv("COUNTRY")) {
    Size len = strlen(var);
    if (len == 2 || len == 3) {
      bool all_digits = true;
      for (int i = 0; i < len; ++i) {
        var[i] = toupper(var[i]);
        if (!isdigit(var[i])) {
          all_digits = false;
        }
      }
      if (all_digits) {
        U16 numeric = atoi(var);
        for (const Country &c : kCountries) {
          if (c.numeric == numeric) {
            return &c;
          }
        }
      } else if (len == 2) {
        for (const Country &c : kCountries) {
          if (c.alpha2[0] == var[0] && c.alpha2[1] == var[1]) {
            return &c;
          }
        }
      } else if (len == 3) {
        for (const Country &c : kCountries) {
          if (c.alpha3[0] == var[0] && c.alpha3[1] == var[1] &&
              c.alpha3[2] == var[2]) {
            return &c;
          }
        }
      }
    }
    for (const Country &c : kCountries) {
      if (c.name == var) {
        return &c;
      }
    }
  }
  return nullptr;
}

// Table of TIMEZONE_PREFIX -> COUNTRY
static const std::pair<StrView, const Country *> kTimezoneToCountry[] = {
    {"ROC", alpha2::TW},                    // Taiwan
    {"NZ", alpha2::NZ},                     // New Zealand
    {"Arctic/Longyearbyen", alpha2::SJ},    // Svalbard and Jan Mayen
    {"Kwajalein", alpha2::MH},              // Marshall Islands
    {"US/Samoa", alpha2::AS},               // American Samoa
    {"US", alpha2::US},                     // United States
    {"Turkey", alpha2::TR},                 // Turkey
    {"GB", alpha2::GB},                     // United Kingdom
    {"Eire", alpha2::IE},                   // Ireland
    {"Libya", alpha2::LY},                  // Libya
    {"Cuba", alpha2::CU},                   // Cuba
    {"Israel", alpha2::IL},                 // Israel
    {"Iran", alpha2::IR},                   // Iran
    {"Asia/Harbin", alpha2::CN},            // China
    {"Asia/Damascus", alpha2::SY},          // Syria
    {"Asia/Dubai", alpha2::AE},             // United Arab Emirates
    {"Asia/Phnom_Penh", alpha2::KH},        // Cambodia
    {"Asia/Ashgabat", alpha2::TM},          // Turkmenistan
    {"Asia/Calcutta", alpha2::IN},          // India
    {"Asia/Kuching", alpha2::MY},           // Malaysia
    {"Asia/Kamchatka", alpha2::RU},         // Russia
    {"Asia/Hovd", alpha2::MN},              // Mongolia
    {"Asia/Aden", alpha2::YE},              // Yemen
    {"Asia/Makassar", alpha2::ID},          // Indonesia
    {"Asia/Kabul", alpha2::AF},             // Afghanistan
    {"Asia/Choibalsan", alpha2::MN},        // Mongolia
    {"Asia/Baku", alpha2::AZ},              // Azerbaijan
    {"Asia/Omsk", alpha2::RU},              // Russia
    {"Asia/Yekaterinburg", alpha2::RU},     // Russia
    {"Asia/Irkutsk", alpha2::RU},           // Russia
    {"Asia/Riyadh", alpha2::SA},            // Saudi Arabia
    {"Asia/Qyzylorda", alpha2::KZ},         // Kazakhstan
    {"Asia/Jayapura", alpha2::ID},          // Indonesia
    {"Asia/Magadan", alpha2::RU},           // Russia
    {"Asia/Shanghai", alpha2::CN},          // China
    {"Asia/Yangon", alpha2::MM},            // Myanmar
    {"Asia/Macau", alpha2::MO},             // Macau
    {"Asia/Istanbul", alpha2::TR},          // Turkey
    {"Asia/Bangkok", alpha2::TH},           // Thailand
    {"Asia/Vientiane", alpha2::LA},         // Laos
    {"Asia/Kashgar", alpha2::CN},           // China
    {"Asia/Khandyga", alpha2::RU},          // Russia
    {"Asia/Jakarta", alpha2::ID},           // Indonesia
    {"Asia/Brunei", alpha2::BN},            // Brunei
    {"Asia/Gaza", alpha2::PS},              // Palestine
    {"Asia/Manila", alpha2::PH},            // Philippines
    {"Asia/Hebron", alpha2::PS},            // Palestine
    {"Asia/Thimbu", alpha2::BT},            // Bhutan
    {"Asia/Seoul", alpha2::KR},             // South Korea
    {"Asia/Sakhalin", alpha2::RU},          // Russia
    {"Asia/Beirut", alpha2::LB},            // Lebanon
    {"Asia/Pontianak", alpha2::ID},         // Indonesia
    {"Asia/Dhaka", alpha2::BD},             // Bangladesh
    {"Asia/Tashkent", alpha2::UZ},          // Uzbekistan
    {"Asia/Almaty", alpha2::KZ},            // Kazakhstan
    {"Asia/Ulaanbaatar", alpha2::MN},       // Mongolia
    {"Asia/Karachi", alpha2::PK},           // Pakistan
    {"Asia/Atyrau", alpha2::KZ},            // Kazakhstan
    {"Asia/Chongqing", alpha2::CN},         // China
    {"Asia/Novokuznetsk", alpha2::RU},      // Russia
    {"Asia/Thimphu", alpha2::BT},           // Bhutan
    {"Asia/Tomsk", alpha2::RU},             // Russia
    {"Asia/Jerusalem", alpha2::IL},         // Israel
    {"Asia/Famagusta", alpha2::CY},         // Cyprus
    {"Asia/Tokyo", alpha2::JP},             // Japan
    {"Asia/Macao", alpha2::MO},             // Macau
    {"Asia/Krasnoyarsk", alpha2::RU},       // Russia
    {"Asia/Kuala_Lumpur", alpha2::MY},      // Malaysia
    {"Asia/Kathmandu", alpha2::NP},         // Nepal
    {"Asia/Kuwait", alpha2::KW},            // Kuwait
    {"Asia/Ujung_Pandang", alpha2::ID},     // Indonesia
    {"Asia/Urumqi", alpha2::CN},            // China
    {"Asia/Pyongyang", alpha2::KP},         // North Korea
    {"Asia/Aqtobe", alpha2::KZ},            // Kazakhstan
    {"Asia/Tbilisi", alpha2::GE},           // Georgia
    {"Asia/Ust-Nera", alpha2::RU},          // Russia
    {"Asia/Aqtau", alpha2::KZ},             // Kazakhstan
    {"Asia/Qostanay", alpha2::KZ},          // Kazakhstan
    {"Asia/Vladivostok", alpha2::RU},       // Russia
    {"Asia/Rangoon", alpha2::MM},           // Myanmar
    {"Asia/Qatar", alpha2::QA},             // Qatar
    {"Asia/Singapore", alpha2::SG},         // Singapore
    {"Asia/Yakutsk", alpha2::RU},           // Russia
    {"Asia/Oral", alpha2::KZ},              // Kazakhstan
    {"Asia/Chungking", alpha2::CN},         // China
    {"Asia/Novosibirsk", alpha2::RU},       // Russia
    {"Asia/Ho_Chi_Minh", alpha2::VN},       // Vietnam
    {"Asia/Katmandu", alpha2::NP},          // Nepal
    {"Asia/Dili", alpha2::TL},              // Timor-Leste
    {"Asia/Ulan_Bator", alpha2::MN},        // Mongolia
    {"Asia/Dushanbe", alpha2::TJ},          // Tajikistan
    {"Asia/Anadyr", alpha2::RU},            // Russia
    {"Asia/Nicosia", alpha2::CY},           // Cyprus
    {"Asia/Kolkata", alpha2::IN},           // India
    {"Asia/Ashkhabad", alpha2::TM},         // Turkmenistan
    {"Asia/Colombo", alpha2::LK},           // Sri Lanka
    {"Asia/Saigon", alpha2::VN},            // Vietnam
    {"Asia/Tel_Aviv", alpha2::IL},          // Israel
    {"Asia/Dacca", alpha2::BD},             // Bangladesh
    {"Asia/Tehran", alpha2::IR},            // Iran
    {"Asia/Baghdad", alpha2::IQ},           // Iraq
    {"Asia/Amman", alpha2::JO},             // Jordan
    {"Asia/Barnaul", alpha2::RU},           // Russia
    {"Asia/Bahrain", alpha2::BH},           // Bahrain
    {"Asia/Hong_Kong", alpha2::HK},         // Hong Kong
    {"Asia/Taipei", alpha2::TW},            // Taiwan
    {"Asia/Bishkek", alpha2::KG},           // Kyrgyzstan
    {"Asia/Yerevan", alpha2::AM},           // Armenia
    {"Asia/Srednekolymsk", alpha2::RU},     // Russia
    {"Asia/Chita", alpha2::RU},             // Russia
    {"Asia/Samarkand", alpha2::UZ},         // Uzbekistan
    {"Asia/Muscat", alpha2::OM},            // Oman
    {"Mexico", alpha2::MX},                 // Mexico
    {"America/Kralendijk", alpha2::BQ},     // Bonaire, Sint Eustatius and Saba
    {"America/Cordoba", alpha2::AR},        // Argentina
    {"America/Lower_Princes", alpha2::SX},  // Sint Maarten
    {"America/Fort_Wayne", alpha2::US},     // United States
    {"America/Merida", alpha2::MX},         // Mexico
    {"America/Tegucigalpa", alpha2::HN},    // Honduras
    {"America/Thunder_Bay", alpha2::CA},    // Canada
    {"America/Port-au-Prince", alpha2::HT}, // Haiti
    {"America/Regina", alpha2::CA},         // Canada
    {"America/Rio_Branco", alpha2::BR},     // Brazil
    {"America/Nipigon", alpha2::CA},        // Canada
    {"America/Bogota", alpha2::CO},         // Colombia
    {"America/St_Lucia", alpha2::LC},       // Saint Lucia
    {"America/Porto_Acre", alpha2::BR},     // Brazil
    {"America/New_York", alpha2::US},       // United States
    {"America/Campo_Grande", alpha2::BR},   // Brazil
    {"America/Dawson", alpha2::CA},         // Canada
    {"America/Eirunepe", alpha2::BR},       // Brazil
    {"America/Cambridge_Bay", alpha2::CA},  // Canada
    {"America/Moncton", alpha2::CA},        // Canada
    {"America/Havana", alpha2::CU},         // Cuba
    {"America/Nuuk", alpha2::GL},           // Greenland
    {"America/Boise", alpha2::US},          // United States
    {"America/Caracas", alpha2::VE},        // Venezuela
    {"America/Resolute", alpha2::CA},       // Canada
    {"America/Bahia", alpha2::BR},          // Brazil
    {"America/Bahia_Banderas", alpha2::MX}, // Mexico
    {"America/Montserrat", alpha2::MS},     // Montserrat
    {"America/Catamarca", alpha2::AR},      // Argentina
    {"America/Miquelon", alpha2::PM},       // Saint Pierre and Miquelon
    {"America/Chihuahua", alpha2::MX},      // Mexico
    {"America/Shiprock", alpha2::US},       // United States
    {"America/Manaus", alpha2::BR},         // Brazil
    {"America/Nome", alpha2::US},           // United States
    {"America/Cancun", alpha2::MX},         // Mexico
    {"America/Mazatlan", alpha2::MX},       // Mexico
    {"America/Montevideo", alpha2::UY},     // Uruguay
    {"America/Lima", alpha2::PE},           // Peru
    {"America/Rankin_Inlet", alpha2::CA},   // Canada
    {"America/St_Vincent", alpha2::VC},     // Saint Vincent and the Grenadines
    {"America/Inuvik", alpha2::CA},         // Canada
    {"America/Atka", alpha2::US},           // United States
    {"America/Santa_Isabel", alpha2::MX},   // Mexico
    {"America/Cuiaba", alpha2::BR},         // Brazil
    {"America/Los_Angeles", alpha2::US},    // United States
    {"America/Barbados", alpha2::BB},       // Barbados
    {"America/Curacao", alpha2::CW},        // Curaçao
    {"America/Managua", alpha2::NI},        // Nicaragua
    {"America/Panama", alpha2::PA},         // Panama
    {"America/St_Thomas", alpha2::VI},      // United States Virgin Islands
    {"America/Guayaquil", alpha2::EC},      // Ecuador
    {"America/Toronto", alpha2::CA},        // Canada
    {"America/Mexico_City", alpha2::MX},    // Mexico
    {"America/Knox_IN", alpha2::US},        // United States
    {"America/Santarem", alpha2::BR},       // Brazil
    {"America/Goose_Bay", alpha2::CA},      // Canada
    {"America/Buenos_Aires", alpha2::AR},   // Argentina
    {"America/Boa_Vista", alpha2::BR},      // Brazil
    {"America/Marigot", alpha2::MF},        // Saint Martin
    {"America/Sao_Paulo", alpha2::BR},      // Brazil
    {"America/Indianapolis", alpha2::US},   // United States
    {"America/Noronha", alpha2::BR},        // Brazil
    {"America/Monterrey", alpha2::MX},      // Mexico
    {"America/Araguaina", alpha2::BR},      // Brazil
    {"America/Fortaleza", alpha2::BR},      // Brazil
    {"America/Port_of_Spain", alpha2::TT},  // Trinidad and Tobago
    {"America/Winnipeg", alpha2::CA},       // Canada
    {"America/Asuncion", alpha2::PY},       // Paraguay
    {"America/Jamaica", alpha2::JM},        // Jamaica
    {"America/Indiana", alpha2::US},        // United States
    {"America/Anguilla", alpha2::AI},       // Anguilla
    {"America/Belize", alpha2::BZ},         // Belize
    {"America/Edmonton", alpha2::CA},       // Canada
    {"America/Anchorage", alpha2::US},      // United States
    {"America/Menominee", alpha2::US},      // United States
    {"America/Mendoza", alpha2::AR},        // Argentina
    {"America/Belem", alpha2::BR},          // Brazil
    {"America/Guatemala", alpha2::GT},      // Guatemala
    {"America/Grand_Turk", alpha2::TC},     // Turks and Caicos Islands
    {"America/Creston", alpha2::CA},        // Canada
    {"America/Atikokan", alpha2::CA},       // Canada
    {"America/Scoresbysund", alpha2::GL},   // Greenland
    {"America/Yellowknife", alpha2::CA},    // Canada
    {"America/Porto_Velho", alpha2::BR},    // Brazil
    {"America/St_Kitts", alpha2::KN},       // Saint Kitts and Nevis
    {"America/Kentucky", alpha2::US},       // United States
    {"America/Kentucky/Monticello", alpha2::US}, // United States
    {"America/Kentucky/Louisville", alpha2::US}, // United States
    {"America/Whitehorse", alpha2::CA},          // Canada
    {"America/Paramaribo", alpha2::SR},          // Suriname
    {"America/El_Salvador", alpha2::SV},         // El Salvador
    {"America/Antigua", alpha2::AG},             // Antigua and Barbuda
    {"America/Halifax", alpha2::CA},             // Canada
    {"America/Costa_Rica", alpha2::CR},          // Costa Rica
    {"America/Ojinaga", alpha2::MX},             // Mexico
    {"America/Santiago", alpha2::CL},            // Chile
    {"America/Yakutat", alpha2::US},             // United States
    {"America/Rosario", alpha2::AR},             // Argentina
    {"America/Cayman", alpha2::KY},              // Cayman Islands
    {"America/Santo_Domingo", alpha2::DO},       // Dominican Republic
    {"America/Ciudad_Juarez", alpha2::MX},       // Mexico
    {"America/Guadeloupe", alpha2::GP},          // Guadeloupe
    {"America/Fort_Nelson", alpha2::CA},         // Canada
    {"America/Nassau", alpha2::BS},              // The Bahamas
    {"America/St_Johns", alpha2::CA},            // Canada
    {"America/Matamoros", alpha2::MX},           // Mexico
    {"America/Hermosillo", alpha2::MX},          // Mexico
    {"America/Sitka", alpha2::US},               // United States
    {"America/Argentina", alpha2::AR},           // Argentina
    {"America/Punta_Arenas", alpha2::CL},        // Chile
    {"America/Tijuana", alpha2::MX},             // Mexico
    {"America/Chicago", alpha2::US},             // United States
    {"America/Blanc-Sablon", alpha2::CA},        // Canada
    {"America/Coral_Harbour", alpha2::BS},       // The Bahamas
    {"America/Metlakatla", alpha2::US},          // United States
    {"America/Dawson_Creek", alpha2::CA},        // Canada
    {"America/Swift_Current", alpha2::CA},       // Canada
    {"America/Recife", alpha2::BR},              // Brazil
    {"America/La_Paz", alpha2::BO},              // Bolivia
    {"America/Guyana", alpha2::GY},              // Guyana
    {"America/Rainy_River", alpha2::CA},         // Canada
    {"America/Tortola", alpha2::VG},             // British Virgin Islands
    {"America/Juneau", alpha2::US},              // United States
    {"America/Iqaluit", alpha2::CA},             // Canada
    {"America/Denver", alpha2::US},              // United States
    {"America/Grenada", alpha2::GD},             // Grenada
    {"America/Jujuy", alpha2::AR},               // Argentina
    {"America/Virgin", alpha2::VI},              // United States Virgin Islands
    {"America/Vancouver", alpha2::CA},           // Canada
    {"America/Martinique", alpha2::MQ},          // Martinique
    {"America/Cayenne", alpha2::GF},             // French Guiana
    {"America/St_Barthelemy", alpha2::BL},       // Saint Barthélemy
    {"America/Godthab", alpha2::GL},             // Greenland
    {"America/Pangnirtung", alpha2::CA},         // Canada
    {"America/Aruba", alpha2::AW},               // Aruba
    {"America/Louisville", alpha2::US},          // United States
    {"America/Thule", alpha2::GL},               // Greenland
    {"America/Montreal", alpha2::CA},            // Canada
    {"America/Maceio", alpha2::BR},              // Brazil
    {"America/Puerto_Rico", alpha2::PR},         // Puerto Rico
    {"America/North_Dakota", alpha2::US},        // United States
    {"America/North_Dakota/New_Salem", alpha2::US}, // United States
    {"America/North_Dakota/Beulah", alpha2::US},    // United States
    {"America/North_Dakota/Center", alpha2::US},    // United States
    {"America/Adak", alpha2::US},                   // United States
    {"America/Ensenada", alpha2::MX},               // Mexico
    {"America/Glace_Bay", alpha2::CA},              // Canada
    {"America/Danmarkshavn", alpha2::GL},           // Greenland
    {"America/Phoenix", alpha2::US},                // United States
    {"America/Detroit", alpha2::US},                // United States
    {"America/Dominica", alpha2::DM},               // Dominica
    {"ROK", alpha2::KR},                            // South Korea
    {"Atlantic/Faeroe", alpha2::FO},                // Faroe Islands
    {"Atlantic/South_Georgia",
     alpha2::GS}, // South Georgia and the South Sandwich Islands
    {"Atlantic/Reykjavik", alpha2::IS},  // Iceland
    {"Atlantic/Faroe", alpha2::FO},      // Faroe Islands
    {"Atlantic/Canary", alpha2::ES},     // Spain
    {"Atlantic/Jan_Mayen", alpha2::SJ},  // Svalbard and Jan Mayen
    {"Atlantic/Cape_Verde", alpha2::CV}, // Cape Verde
    {"Atlantic/St_Helena",
     alpha2::SH}, // Saint Helena, Ascension and Tristan da Cunha
    {"Atlantic/Bermuda", alpha2::BM},          // Bermuda
    {"Atlantic/Azores", alpha2::PT},           // Portugal
    {"Atlantic/Stanley", alpha2::FK},          // Falkland Islands
    {"Atlantic/Madeira", alpha2::PT},          // Portugal
    {"Jamaica", alpha2::JM},                   // Jamaica
    {"Iceland", alpha2::IS},                   // Iceland
    {"Chile", alpha2::CL},                     // Chile
    {"Antarctica/Rothera", alpha2::AQ},        // Antarctica
    {"Antarctica/Syowa", alpha2::AQ},          // Antarctica
    {"Antarctica/McMurdo", alpha2::AQ},        // Antarctica
    {"Antarctica/DumontDUrville", alpha2::AQ}, // Antarctica
    {"Antarctica/Macquarie", alpha2::AU},      // Australia
    {"Antarctica/Vostok", alpha2::AQ},         // Antarctica
    {"Antarctica/South_Pole", alpha2::AQ},     // Antarctica
    {"Antarctica/Casey", alpha2::AQ},          // Antarctica
    {"Antarctica/Palmer", alpha2::AQ},         // Antarctica
    {"Antarctica/Troll", alpha2::AQ},          // Antarctica
    {"Antarctica/Mawson", alpha2::AQ},         // Antarctica
    {"Antarctica/Davis", alpha2::AQ},          // Antarctica
    {"Indian/Kerguelen", alpha2::TF},     // French Southern and Antarctic Lands
    {"Indian/Reunion", alpha2::RE},       // Réunion
    {"Indian/Chagos", alpha2::IO},        // British Indian Ocean Territory
    {"Indian/Maldives", alpha2::MV},      // Maldives
    {"Indian/Mayotte", alpha2::YT},       // Mayotte
    {"Indian/Christmas", alpha2::CX},     // Christmas Island
    {"Indian/Mahe", alpha2::SC},          // Seychelles
    {"Indian/Mauritius", alpha2::MU},     // Mauritius
    {"Indian/Cocos", alpha2::CC},         // Cocos Keeling Islands
    {"Indian/Comoro", alpha2::KM},        // Comoros
    {"Indian/Antananarivo", alpha2::MG},  // Madagascar
    {"Singapore", alpha2::SG},            // Singapore
    {"Portugal", alpha2::PT},             // Portugal
    {"Pacific/Noumea", alpha2::NC},       // New Caledonia
    {"Pacific/Enderbury", alpha2::KI},    // Kiribati
    {"Pacific/Apia", alpha2::WS},         // Samoa
    {"Pacific/Kwajalein", alpha2::MH},    // Marshall Islands
    {"Pacific/Ponape", alpha2::FM},       // Federated States of Micronesia
    {"Pacific/Majuro", alpha2::MH},       // Marshall Islands
    {"Pacific/Chatham", alpha2::NZ},      // New Zealand
    {"Pacific/Bougainville", alpha2::PG}, // Papua New Guinea
    {"Pacific/Guadalcanal", alpha2::SB},  // Solomon Islands
    {"Pacific/Tahiti", alpha2::PF},       // French Polynesia
    {"Pacific/Truk", alpha2::FM},         // Federated States of Micronesia
    {"Pacific/Kiritimati", alpha2::KI},   // Kiribati
    {"Pacific/Tarawa", alpha2::KI},       // Kiribati
    {"Pacific/Gambier", alpha2::PF},      // French Polynesia
    {"Pacific/Easter", alpha2::CL},       // Chile
    {"Pacific/Midway", alpha2::UM},   // United States Minor Outlying Islands
    {"Pacific/Yap", alpha2::FM},      // Federated States of Micronesia
    {"Pacific/Saipan", alpha2::MP},   // Northern Mariana Islands
    {"Pacific/Honolulu", alpha2::US}, // United States
    {"Pacific/Chuuk", alpha2::FM},    // Federated States of Micronesia
    {"Pacific/Kanton", alpha2::KI},   // Kiribati
    {"Pacific/Guam", alpha2::GU},     // Guam
    {"Pacific/Port_Moresby", alpha2::PG}, // Papua New Guinea
    {"Pacific/Pago_Pago", alpha2::AS},    // American Samoa
    {"Pacific/Fiji", alpha2::FJ},         // Fiji
    {"Pacific/Auckland", alpha2::NZ},     // New Zealand
    {"Pacific/Nauru", alpha2::NR},        // Nauru
    {"Pacific/Efate", alpha2::VU},        // Vanuatu
    {"Pacific/Norfolk", alpha2::NF},      // Norfolk Island
    {"Pacific/Palau", alpha2::PW},        // Palau
    {"Pacific/Kosrae", alpha2::FM},       // Federated States of Micronesia
    {"Pacific/Galapagos", alpha2::EC},    // Ecuador
    {"Pacific/Funafuti", alpha2::TV},     // Tuvalu
    {"Pacific/Marquesas", alpha2::PF},    // French Polynesia
    {"Pacific/Niue", alpha2::NU},         // Niue
    {"Pacific/Rarotonga", alpha2::CK},    // Cook Islands
    {"Pacific/Samoa", alpha2::WS},        // Samoa
    {"Pacific/Wallis", alpha2::WF},       // Wallis and Futuna
    {"Pacific/Pohnpei", alpha2::FM},      // Federated States of Micronesia
    {"Pacific/Tongatapu", alpha2::TO},    // Tonga
    {"Pacific/Fakaofo", alpha2::TK},      // Tokelau
    {"Pacific/Wake", alpha2::UM},     // United States Minor Outlying Islands
    {"Pacific/Pitcairn", alpha2::PN}, // Pitcairn Islands
    {"Pacific/Johnston", alpha2::UM}, // United States Minor Outlying Islands
    {"Poland", alpha2::PL},           // Poland
    {"Africa/Abidjan", alpha2::CI},   // Côte d'Ivoire
    {"Africa/Dar_es_Salaam", alpha2::TZ}, // Tanzania
    {"Africa/Accra", alpha2::GH},         // Ghana
    {"Africa/Luanda", alpha2::AO},        // Angola
    {"Africa/Windhoek", alpha2::NA},      // Namibia
    {"Africa/Djibouti", alpha2::DJ},      // Djibouti
    {"Africa/Lome", alpha2::TG},          // Togo
    {"Africa/Maputo", alpha2::MZ},        // Mozambique
    {"Africa/Lagos", alpha2::NG},         // Nigeria
    {"Africa/Johannesburg", alpha2::ZA},  // South Africa
    {"Africa/Monrovia", alpha2::LR},      // Liberia
    {"Africa/Juba", alpha2::SS},          // South Sudan
    {"Africa/Nairobi", alpha2::KE},       // Kenya
    {"Africa/Addis_Ababa", alpha2::ET},   // Ethiopia
    {"Africa/Malabo", alpha2::GQ},        // Equatorial Guinea
    {"Africa/Tunis", alpha2::TN},         // Tunisia
    {"Africa/Ceuta", alpha2::ES},         // Spain
    {"Africa/Bissau", alpha2::GW},        // Guinea-Bissau
    {"Africa/Brazzaville", alpha2::CG},   // Congo-Brazzaville
    {"Africa/Asmera", alpha2::ER},        // Eritrea
    {"Africa/Nouakchott", alpha2::MR},    // Mauritania
    {"Africa/Lusaka", alpha2::ZM},        // Zambia
    {"Africa/Freetown", alpha2::SL},      // Sierra Leone
    {"Africa/Maseru", alpha2::LS},        // Lesotho
    {"Africa/Kigali", alpha2::RW},        // Rwanda
    {"Africa/Banjul", alpha2::GM},        // The Gambia
    {"Africa/Kinshasa", alpha2::CD},      // Democratic Republic of the Congo
    {"Africa/Bangui", alpha2::CF},        // Central African Republic
    {"Africa/Asmara", alpha2::ER},        // Eritrea
    {"Africa/El_Aaiun", alpha2::EH},      // Western Sahara
    {"Africa/Sao_Tome", alpha2::ST},      // Sao Tome and Principe
    {"Africa/Khartoum", alpha2::SD},      // Sudan
    {"Africa/Dakar", alpha2::SN},         // Senegal
    {"Africa/Casablanca", alpha2::MA},    // Morocco
    {"Africa/Gaborone", alpha2::BW},      // Botswana
    {"Africa/Conakry", alpha2::GN},       // Guinea
    {"Africa/Bujumbura", alpha2::BI},     // Burundi
    {"Africa/Douala", alpha2::CM},        // Cameroon
    {"Africa/Lubumbashi", alpha2::CD},    // Democratic Republic of the Congo
    {"Africa/Harare", alpha2::ZW},        // Zimbabwe
    {"Africa/Mbabane", alpha2::SZ},       // Eswatini
    {"Africa/Ndjamena", alpha2::TD},      // Chad
    {"Africa/Ouagadougou", alpha2::BF},   // Burkina Faso
    {"Africa/Niamey", alpha2::NE},        // Niger
    {"Africa/Porto-Novo", alpha2::BJ},    // Benin
    {"Africa/Kampala", alpha2::UG},       // Uganda
    {"Africa/Bamako", alpha2::ML},        // Mali
    {"Africa/Blantyre", alpha2::MW},      // Malawi
    {"Africa/Algiers", alpha2::DZ},       // Algeria
    {"Africa/Libreville", alpha2::GA},    // Gabon
    {"Africa/Mogadishu", alpha2::SO},     // Somalia
    {"Africa/Tripoli", alpha2::LY},       // Libya
    {"Africa/Timbuktu", alpha2::ML},      // Mali
    {"Africa/Cairo", alpha2::EG},         // Egypt
    {"PRC", alpha2::CN},                  // China
    {"GB-Eire", alpha2::GB},              // United Kingdom
    {"Brazil", alpha2::BR},               // Brazil
    {"Hongkong", alpha2::HK},             // Hong Kong
    {"Japan", alpha2::JP},                // Japan
    {"HST", alpha2::US},                  // United States - Hawaii
    {"Navajo", alpha2::US},               // United States - Navajo Nation
    {"Australia", alpha2::AU},            // Australia
    {"Egypt", alpha2::EG},                // Egypt
    {"Europe/Sarajevo", alpha2::BA},      // Bosnia and Herzegovina
    {"Europe/Kiev", alpha2::UA},          // Ukraine
    {"Europe/Zurich", alpha2::CH},        // Switzerland
    {"Europe/Monaco", alpha2::MC},        // Monaco
    {"Europe/Tiraspol", alpha2::MD},      // Transnistria (missing country code)
    {"Europe/Helsinki", alpha2::FI},      // Finland
    {"Europe/Ulyanovsk", alpha2::RU},     // Russia
    {"Europe/Zagreb", alpha2::HR},        // Croatia
    {"Europe/Uzhgorod", alpha2::UA},      // Ukraine
    {"Europe/Minsk", alpha2::BY},         // Belarus
    {"Europe/Malta", alpha2::MT},         // Malta
    {"Europe/Brussels", alpha2::BE},      // Belgium
    {"Europe/Saratov", alpha2::RU},       // Russia
    {"Europe/Isle_of_Man", alpha2::IM},   // Isle of Man
    {"Europe/Madrid", alpha2::ES},        // Spain
    {"Europe/Chisinau", alpha2::MD},      // Moldova
    {"Europe/Istanbul", alpha2::TR},      // Turkey
    {"Europe/Bucharest", alpha2::RO},     // Romania
    {"Europe/Warsaw", alpha2::PL},        // Poland
    {"Europe/Volgograd", alpha2::RU},     // Russia
    {"Europe/Tirane", alpha2::AL},        // Albania
    {"Europe/Oslo", alpha2::NO},          // Norway
    {"Europe/Zaporozhye", alpha2::UA},    // Ukraine
    {"Europe/Copenhagen", alpha2::DK},    // Denmark
    {"Europe/Bratislava", alpha2::SK},    // Slovakia
    {"Europe/Tallinn", alpha2::EE},       // Estonia
    {"Europe/Riga", alpha2::LV},          // Latvia
    {"Europe/Amsterdam", alpha2::NL},     // Netherlands
    {"Europe/Gibraltar", alpha2::GI},     // Gibraltar
    {"Europe/Guernsey", alpha2::GG},      // Guernsey
    {"Europe/Berlin", alpha2::DE},        // Germany
    {"Europe/Kaliningrad", alpha2::RU},   // Russia
    {"Europe/Dublin", alpha2::IE},        // Ireland
    {"Europe/Belfast", alpha2::GB},       // United Kingdom
    {"Europe/Andorra", alpha2::AD},       // Andorra
    {"Europe/Ljubljana", alpha2::SI},     // Slovenia
    {"Europe/Belgrade", alpha2::RS},      // Serbia
    {"Europe/London", alpha2::GB},        // United Kingdom
    {"Europe/Budapest", alpha2::HU},      // Hungary
    {"Europe/Paris", alpha2::FR},         // France
    {"Europe/Rome", alpha2::IT},          // Italy
    {"Europe/Lisbon", alpha2::PT},        // Portugal
    {"Europe/Vilnius", alpha2::LT},       // Lithuania
    {"Europe/Stockholm", alpha2::SE},     // Sweden
    {"Europe/Vatican", alpha2::VA},       // Vatican City
    {"Europe/Jersey", alpha2::JE},        // Jersey
    {"Europe/Kirov", alpha2::RU},         // Russia
    {"Europe/Skopje", alpha2::MK},        // North Macedonia
    {"Europe/Simferopol", alpha2::UA},    // Ukraine
    {"Europe/Astrakhan", alpha2::RU},     // Russia
    {"Europe/Podgorica", alpha2::ME},     // Montenegro
    {"Europe/Vaduz", alpha2::LI},         // Liechtenstein
    {"Europe/Kyiv", alpha2::UA},          // Ukraine
    {"Europe/Moscow", alpha2::RU},        // Russia
    {"Europe/Nicosia", alpha2::CY},       // Cyprus
    {"Europe/Busingen", alpha2::DE},      // Germany
    {"Europe/Luxembourg", alpha2::LU},    // Luxembourg
    {"Europe/San_Marino", alpha2::SM},    // San Marino
    {"Europe/Vienna", alpha2::AT},        // Austria
    {"Europe/Mariehamn", alpha2::AX},     // Åland Islands
    {"Europe/Samara", alpha2::RU},        // Russia
    {"Europe/Prague", alpha2::CZ},        // Czech Republic
    {"Europe/Sofia", alpha2::BG},         // Bulgaria
    {"Europe/Athens", alpha2::GR},        // Greece
    {"Canada", alpha2::CA},               // Canada
};

static const Country *GetMachineCountryFromTimezone() {
  Status status;
  Str timezone = fs::Read(fs::real, "/etc/timezone", status);
  if (!OK(status)) {
    status.Reset();
    // Try getting symlink
    Path target = Path("/etc/localtime").ReadLink(status);
    if (target.str.starts_with("/usr/share/zoneinfo/")) {
      timezone = target.str.substr(20);
    } else {
      return nullptr;
    }
  }
  StripWhitespace(timezone);
  for (auto &tz : kTimezoneToCountry) {
    if (timezone.starts_with(tz.first)) {
      return tz.second;
    }
  }
  return nullptr;
}

static const Country *LangStringToCountry(Str lang) {
  Size underscore = lang.find('_');
  if (underscore == Str::npos) {
    return nullptr;
  }
  if (lang.size() < underscore + 3) {
    return nullptr;
  }
  auto country = lang.substr(underscore + 1, 2);
  for (auto &c : kCountries) {
    if (c.alpha2[0] == country[0] && c.alpha2[1] == country[1]) {
      return &c;
    }
  }
  return nullptr;
}

static const Country *GetMachineCountryFromLang() {
  if (char *lang = getenv("LANG")) {
    if (auto country = LangStringToCountry(lang)) {
      return country;
    }
  }
  if (char *language = getenv("LANGUAGE")) {
    if (auto country = LangStringToCountry(language)) {
      return country;
    }
  }
  return nullptr;
}

static const Country *GetMachineCountrySlow() {
  if (auto country_from_env = GetMachineCountryFromEnv()) {
    return country_from_env;
  }
  if (auto country_from_timezone = GetMachineCountryFromTimezone()) {
    return country_from_timezone;
  }
  if (auto country_from_lang = GetMachineCountryFromLang()) {
    return country_from_lang;
  }
  return nullptr;
}

const Country *GetMachineCountry() {
  static const Country *cached_country = GetMachineCountrySlow();
  return cached_country;
}

} // namespace maf
