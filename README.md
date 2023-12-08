# Crackme Resolver ZeroNight15. Keygen для crackme sampl'а

## Задача - решить crackme с ZeroNight15 от Kaspersky. Необходимо найти пару ```{email, serial}``` или просто ```{serial}``` для конкретного ```email```

## Для корректной работы необоходимо  ```ida```, ```ProcessHacker2```

### <https://hex-rays.com/ida-free/>

### <https://github.com/fengjixuchui/ProcessHacker-2>

## Reverse crackme_zn15_02-31158-4af5cd.exe (dump payload'а)

![alt text](/img/payload.gif)

## Reverse payload_decrypt_0x1a60000-0x6a000(0x69c00-433152).exe

```C
char __cdecl check_mail_serial(char *email, int email_length, char *serial, int serial_length)
{
  char *pointer_serial; // edi
  unsigned int v5; // ebx
  int v6; // eax
  char *pointer_zeronights_hash_md5; // ecx
  char *pointer_calculated_hash; // edx
  unsigned int serial_length_sub_4; // esi
  bool last_dword_reached; // cf
  int serial_2byte_hex; // [esp+Ch] [ebp-88h] BYREF
  unsigned int serial_length_div_2; // [esp+10h] [ebp-84h]
  int email_hash_md5_2byte_hex; // [esp+14h] [ebp-80h] BYREF
  char email_hash_md5[40]; // [esp+18h] [ebp-7Ch] BYREF
  char zeronights_hash_md5[40]; // [esp+40h] [ebp-54h] BYREF
  char calculated_hash[40]; // [esp+68h] [ebp-2Ch] BYREF

  pointer_serial = serial;
  if ( !email || !email_length )
    return 0;
  if ( serial && serial_length )
  {
    if ( (serial_length * serial_length - 24) % 1000u || (unsigned int)(serial_length - 10) > 30 )
      return 0;
    MD5(email, (int)email_hash_md5);
    MD5("Z3r0_N1ghts", (int)zeronights_hash_md5);
    v5 = 0;
    serial_length_div_2 = (unsigned int)serial_length >> 1;
    if ( (unsigned int)serial_length >> 1 )
    {
      v6 = email_hash_md5 - serial;
      while ( unknown_libname_2(&pointer_serial[v6], "%2x", (int)&email_hash_md5_2byte_hex)
           && unknown_libname_2(pointer_serial, "%2x", (int)&serial_2byte_hex) )
      {
        sprintf(
          &pointer_serial[calculated_hash - serial],
          "%02x",
          (unsigned __int8)(email_hash_md5_2byte_hex + serial_2byte_hex));
        v6 = email_hash_md5 - serial;
        ++v5;
        pointer_serial += 2;
        if ( v5 >= serial_length_div_2 )
          goto LABEL_12;
      }
      return 0;
    }
LABEL_12:
    pointer_zeronights_hash_md5 = zeronights_hash_md5;
    pointer_calculated_hash = calculated_hash;
    serial_length_sub_4 = serial_length - 4;
    if ( (unsigned int)serial_length < 4 )
    {
LABEL_15:
      if ( serial_length_sub_4 == -4 )
      {
TRUE_RETURN:
        email_hash_md5_2byte_hex = 1;
        return 1;
      }
    }
    else
    {
      while ( *(_DWORD *)pointer_zeronights_hash_md5 == *(_DWORD *)pointer_calculated_hash )
      {
        pointer_zeronights_hash_md5 += 4;
        pointer_calculated_hash += 4;
        last_dword_reached = serial_length_sub_4 < 4;
        serial_length_sub_4 -= 4;
        if ( last_dword_reached )
          goto LABEL_15;
      }
    }
    if ( *pointer_zeronights_hash_md5 != *pointer_calculated_hash
      || serial_length_sub_4 != -3
      && (pointer_zeronights_hash_md5[1] != pointer_calculated_hash[1]
       || serial_length_sub_4 != -2
       && (pointer_zeronights_hash_md5[2] != pointer_calculated_hash[2]
        || serial_length_sub_4 != -1 && pointer_zeronights_hash_md5[3] != pointer_calculated_hash[3])) )
    {
      email_hash_md5_2byte_hex = 0;
      return 0;
    }
    goto TRUE_RETURN;
  }
  return 0;
}
```

![alt text](/img/calculation.gif)

## Сэмпл crackme и payload находятся в папке ```bin```. Результаты выводятся в ```CLI```

## Используйте методы: ```generate_pair``` для генератора пары ```{email, serial}``` или ```generate_serial``` для генератора ```{serial}``` класса ```CrackmeResolver```

## Примеры результатов

```PYTHON
[+] Success: 
        email is: 'Z3r0_N1ghts'
        serial is: '00000000000000000000000000000000'
[+] Success:
        email is: 'info@kaspersky.com'
        serial is: '723237381ba25dbbc655c08b147b470e'
[+] Success:
        email is: 'W={#SxekRmbg<yy"^ztp'
        serial is: '7ccd8f882741603123e4ec5a79149dc1'
```
