// This file is part of the Qrypto project
// Copyright (C) 2008-2010 Amine Roukh <amineroukh@gmail.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; If not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


#ifndef HEADER_WINDOW
#define HEADER_WINDOW

#include <QtGui>
#include "Hashes.h"
#include "Encryptions.h"
#include "Conversions.h"
#include "History.h"
#include "About.h"
#include "BruteForce.h"


class GenerateKey : public QDialog
{
    Q_OBJECT

public :
    GenerateKey(QWidget *parent=0);

    QCheckBox *upperCase;
    QCheckBox *lowerCase;
    QCheckBox *numbers;
    QCheckBox *speChar;
    QSpinBox *lenth;

private :
    QPushButton *okButton;
    QPushButton *cancelButton;
    QLabel *lenthLabel;
};

class Window : public QWidget
{
    Q_OBJECT

public :
    Window();
    enum functions {separator, Adler32=1, CRC32, MD2, MD4, MD5, RIPEMD128, RIPEMD160, RIPEMD320, SHA1, SHA224, SHA256, SHA384, SHA512, Tiger, Whirlpool,
                    separator1, AES, AES_D, Blowfish, Blowfish_D, Camellia, Camellia_D, CAST128, CAST128_D, CAST256, CAST256_D,
                    DES, DES_D, DES_EDE2, DES_EDE2_D, DES_EDE3, DES_EDE3_D, DES_XEX3, DES_XEX3_D, GOST, GOST_D, IDEA, IDEA_D, MARS,
                    MARS_D, Panama, Panama_D, RC2, RC2_D, RC5, RC5_D, RC6, RC6_D, SAFER_K, SAFER_K_D, SAFER_SK, SAFER_SK_D, Salsa20, Salsa20_D, SEED, SEED_D, SEAL, SEAL_D, Serpent, Serpent_D,
                    SHACAL2, SHACAL2_D, SHARK, SHARK_D, SKIPJACK, SKIPJACK_D, Sosemanuk, Sosemanuk_D, Square, Square_D, TEA, TEA_D, ThreeWay, ThreeWay_D,
                    Twofish, Twofish_D, XSalsa20, XSalsa20_D, XTEA, XTEA_D,
                    separator2, Base32Encode, Base32Decode, Base64Encode, Base64Decode, HexEncode, HexDecode, LeetSpeakEncode, LeetSpeakDecode, Reverse, Rot13Encode,
					URLEncode, URLDecode, UUEncode, UUDecode
                   };

protected:
    void closeEvent(QCloseEvent *event);

public slots:
    void selectFun();
    void clear();
    void swap();
    void copy();
    void about();
    void stayOnTop();
    void historySlot();
    void bruteForceSlot();
    void generateKeyOptSlot();
    void generateKeyFunSlot();
    void grabSignal(QString);

private :
    void inputsEnable(bool stat);
    void readSettings();
    void writeSettings();

    HistoryWindow *historyWindow;
    GenerateKey *genKeyDialog;
    About *aboutDialog;
    BruteForce *bruteForceDialog;
    Hashes *hash;
    Conversion *conv;
    Encryption *encry;

    QVBoxLayout *mainLayout;
    QComboBox *functionSelect;
    QTextEdit *input;
    QLineEdit *key;
    QTextEdit *output;
    QLabel *functionLabel;
    QLabel *inputLabel;
    QLabel *keyLabel;
    QLabel *outputLabel;
    QHBoxLayout *butLayout;
    QHBoxLayout *keyGenLayout;
    QPushButton *generateKeyBut;
    QPushButton *toolsBut;
    QPushButton *clearBut;
    QPushButton *swapBut;
    QPushButton *copyBut;
    QPushButton *aboutBut;
    QAction *lowercase;
    QAction *windowStaysOnTop;
    QAction *history;
    QAction *generateKey;
    QAction *bruteForceBut;
};

#endif
