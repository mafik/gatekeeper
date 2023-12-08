#pragma once

#include "arr.hh"
#include "int.hh"
#include "str.hh"

namespace maf {

namespace iso3166 {

struct Country {
  StrView name;
  char alpha2[2];
  char alpha3[3];
  U16 numeric;
};

inline Str ToStr(const Country &c) { return Str(c.name); }
static_assert(Stringer<iso3166::Country>);

extern const Arr<Country, 249> kCountries;

namespace alpha2 {

extern const Country *AF, *AL, *DZ, *AS, *AD, *AO, *AI, *AQ, *AG, *AR, *AM, *AW,
    *AU, *AT, *AZ, *BS, *BH, *BD, *BB, *BY, *BE, *BZ, *BJ, *BM, *BT, *BO, *BQ,
    *BA, *BW, *BV, *BR, *IO, *BN, *BG, *BF, *BI, *CV, *KH, *CM, *CA, *KY, *CF,
    *TD, *CL, *CN, *CX, *CC, *CO, *KM, *CD, *CG, *CK, *CR, *HR, *CU, *CW, *CY,
    *CZ, *CI, *DK, *DJ, *DM, *DO, *EC, *EG, *SV, *GQ, *ER, *EE, *SZ, *ET, *FK,
    *FO, *FJ, *FI, *FR, *GF, *PF, *TF, *GA, *GM, *GE, *DE, *GH, *GI, *GR, *GL,
    *GD, *GP, *GU, *GT, *GG, *GN, *GW, *GY, *HT, *HM, *VA, *HN, *HK, *HU, *IS,
    *IN, *ID, *IR, *IQ, *IE, *IM, *IL, *IT, *JM, *JP, *JE, *JO, *KZ, *KE, *KI,
    *KP, *KR, *KW, *KG, *LA, *LV, *LB, *LS, *LR, *LY, *LI, *LT, *LU, *MO, *MG,
    *MW, *MY, *MV, *ML, *MT, *MH, *MQ, *MR, *MU, *YT, *MX, *FM, *MD, *MC, *MN,
    *ME, *MS, *MA, *MZ, *MM, *NA, *NR, *NP, *NL, *NC, *NZ, *NI, *NE, *NG, *NU,
    *NF, *MP, *NO, *OM, *PK, *PW, *PS, *PA, *PG, *PY, *PE, *PH, *PN, *PL, *PT,
    *PR, *QA, *MK, *RO, *RU, *RW, *RE, *BL, *SH, *KN, *LC, *MF, *PM, *VC, *WS,
    *SM, *ST, *SA, *SN, *RS, *SC, *SL, *SG, *SX, *SK, *SI, *SB, *SO, *ZA, *GS,
    *SS, *ES, *LK, *SD, *SR, *SJ, *SE, *CH, *SY, *TW, *TJ, *TZ, *TH, *TL, *TG,
    *TK, *TO, *TT, *TN, *TR, *TM, *TC, *TV, *UG, *UA, *AE, *GB, *UM, *US, *UY,
    *UZ, *VU, *VE, *VN, *VG, *VI, *WF, *EH, *YE, *ZM, *ZW, *AX;

} // namespace alpha2

} // namespace iso3166

// Get the country of the current machine.
//
// This method will first inspect the environment variable `COUNTRY` and then
// attempt several heuristic methods to guess the country:
//
//   - Check /etc/timezone against known timezone => country mapping
//   - Check /etc/localtime symlink similarly to above
//   - Check LANG & LANGUAGE environment variables for ll_CC format
//
// Returns nullptr if no country could be determined.
const iso3166::Country *GetMachineCountry();

} // namespace maf