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


#include <string.h>
#include "Window.h"


using namespace std;
using namespace CryptoPP;

Window::Window() : QWidget()
{
    functionLabel = new QLabel(tr("Function :"));

    QStringList functionList;
    functionList << "Hashing ------------------"
    << "Adler32 (Checksum)" << "CRC32 (Cyclic Redundancy Check)" << "MD2 (Message Digest 2)" << "MD4 (Message Digest 4)" << "MD5 (Message Digest 5)"
    << "RIPEMD-128 (RACE Integrity Primitives Evaluation Message Digest)"
    << "RIPEMD-160 (RACE Integrity Primitives Evaluation Message Digest)" << "RIPEMD-320 (RACE Integrity Primitives Evaluation Message Digest)"
    << "SHA-1 (Secure Hash Algorithm)" << "SHA-224 (Secure Hash Algorithm)" << "SHA-256 (Secure Hash Algorithm)" << "SHA-384 (Secure Hash Algorithm)"
    << "SHA-512 (Secure Hash Algorithm)" << "Tiger (192bit Cryptographic Hash Function)" << "Whirlpool (512bit Cryptographic Hash Function)"
    << "Encryption ------------------"
    << "AES (Rijndeal - Encrypt)" << "AES (Rijndeal - Decrypt)" << "Blowfish (Encrypt)" << "Blowfish (Decrypt)" << "Camellia (Encrypt)" << "Camellia (Decrypt)"
    << "CAST128 (Encrypt)" << "CAST128 (Decrypt)" << "CAST256 (Encrypt)" << "CAST256 (Decrypt)" << "DES (Data Encryption Standard - Encrypt)" << "DES (Data Encryption Standard - Decrypt)"
    << "DES 2 (Data Encryption Standard - Encrypt)" << "DES 2 (Data Encryption Standard - Decrypt)" << "DES 3 (Data Encryption Standard - Encrypt)" << "DES 3 (Data Encryption Standard - Decrypt)" << "DES X3 (Data Encryption Standard - Encrypt)" << "DES X3 (Data Encryption Standard - Decrypt)" << "GOST (Encrypt)"
    << "GOST (Decrypt)" << "IDEA (Encrypt)" << "IDEA (Decrypt)" << "MARS (Encrypt)" << "MARS (Decrypt)" << "Panama (Encrypt)" << "Panama (Decrypt)" << "RC2 (Rivest Cipher 2 - Encrypt)" << "RC2 (Rivest Cipher 2 - Decrypt)"
    << "RC5 (Rivest Cipher 5 - Encrypt)" << "RC5 (Rivest Cipher 5 - Decrypt)" << "RC6 (Rivest Cipher 6 - Encrypt)" << "RC6 (Rivest Cipher 6 - Decrypt)" << "SAFER_K (Encrypt)" << "SAFER_K (Decrypt)"
    << "SAFER_SK (Encrypt)" << "SAFER_SK (Decrypt)" << "Salsa20 (Encrypt)" << "Salsa20 (Decrypt)" << "SEAL (Software-Optimized Encryption Algorithm - Encrypt)" << "SEAL (Software-Optimized Encryption Algorithm - Decrypt)" << "SEED (Encrypt)" << "SEED (Decrypt)" << "Serpent (Encrypt)" << "Serpent (Decrypt)" << "SHACAL2 (Encrypt)" << "SHACAL2 (Decrypt)"
    << "SHARK (Encrypt)" << "SHARK (Decrypt)" << "SKIPJACK (Encrypt)" << "SKIPJACK (Decrypt)" << "Sosemanuk (Encrypt)" << "Sosemanuk (Decrypt)" << "Square (Encrypt)" << "Square (Decrypt)"
    << "TEA (Tiny Encryption Algorithm - Encrypt)" << "TEA (Tiny Encryption Algorithm - Decrypt)" << "ThreeWay (Encrypt)" << "ThreeWay (Decrypt)" << "Twofish (Encrypt)" << "Twofish (Decrypt)"
    << "XSalsa20 (Encrypt)" << "XSalsa20 (Decrypt)" << "XTEA (Tiny Encryption Algorithm - Encrypt)" << "XTEA (Tiny Encryption Algorithm - Decrypt)"
    << "Conversions ------------------"
    << "Base32Encode" << "Base32Decode" << "Base64Encode" << "Base64Decode" << "HexEncode" << "HexDecode" << "Leet Speak Encode" << "Leet Speak Decode" << "Reverse String" << "ROT13 Encode" 
	<< "URLEncode" << "URLDecode" << "UUEncode" << "UUDecode";


    functionSelect = new QComboBox();
    functionSelect->addItems(functionList);

    inputLabel = new QLabel(tr("Input :"));
    input = new QTextEdit();
    input->setAcceptRichText(true);
    connect(input, SIGNAL(textChanged()), this, SLOT(selectFun()));

    keyLabel = new QLabel(tr("Key :"));
    key = new QLineEdit();
    connect(key, SIGNAL(textChanged(QString)), this, SLOT(selectFun()));
    key->setReadOnly(true);

    generateKeyBut = new QPushButton("<<");
    generateKeyBut->setToolTip("Generate Key");
    connect(generateKeyBut, SIGNAL(clicked()), this, SLOT(generateKeyFunSlot()));
    generateKeyBut->setEnabled(false);

    keyGenLayout = new QHBoxLayout();
    keyGenLayout->addWidget(key);
    keyGenLayout->addWidget(generateKeyBut);

    outputLabel = new QLabel(tr("Output :"));
    output = new QTextEdit();
    output->setAcceptRichText(true);
    output->setReadOnly(true);

    toolsBut = new QPushButton(QIcon(":/data/settings.png"), tr("&Tools"), this);
    clearBut = new QPushButton(QIcon(":/data/edit-clear.png"), tr("&Clear"), this);
    connect(clearBut, SIGNAL(clicked()), this, SLOT(clear()));
    swapBut = new QPushButton(QIcon(":/data/swap.png"), tr("S&wap"), this);
    connect(swapBut, SIGNAL(clicked()), this, SLOT(swap()));
    copyBut = new QPushButton(QIcon(":/data/edit-copy.png"), tr("&Copy"), this);
    connect(copyBut, SIGNAL(clicked()), this, SLOT(copy()));
    aboutBut = new QPushButton(QIcon(":/data/qrypto.png"), tr("&About"));
    connect(aboutBut, SIGNAL(clicked()), this, SLOT(about()));

    inputsEnable(false);

    windowStaysOnTop = new QAction(QIcon(":/data/window-top.png"), tr("Stay on to&p"), this);
    windowStaysOnTop->setCheckable(true);
    connect(windowStaysOnTop, SIGNAL(triggered()), this, SLOT(stayOnTop()));
    lowercase = new QAction(QIcon(":/data/lower.png"), tr("Output in &lowercase"), this);
    lowercase->setCheckable(true);
    connect(lowercase, SIGNAL(triggered()), this, SLOT(selectFun()));
    history = new QAction(QIcon(":/data/history.png"), tr("&MemoAera"), this);
    connect(history, SIGNAL(triggered()), this, SLOT(historySlot()));
    generateKey = new QAction(QIcon(":/data/roll.png"), tr("&Generate key"), this);
    connect(generateKey, SIGNAL(triggered()), this, SLOT(generateKeyOptSlot()));
    bruteForceBut = new QAction(QIcon(":/data/bruteforce.png"), tr("&Brute Forcer"), this);
    connect(bruteForceBut, SIGNAL(triggered()), this, SLOT(bruteForceSlot()));

    QMenu *menu = new QMenu(this);
    menu->addAction(windowStaysOnTop);
    menu->addAction(lowercase);
    menu->addAction(history);
    menu->addAction(generateKey);
    menu->addAction(bruteForceBut);
    toolsBut->setMenu(menu);

    butLayout = new QHBoxLayout();
    butLayout->addWidget(toolsBut);
    butLayout->addWidget(clearBut);
    butLayout->addWidget(swapBut);
    butLayout->addWidget(copyBut);
    butLayout->addWidget(aboutBut);

    mainLayout = new QVBoxLayout();
    mainLayout->addWidget(functionLabel);
    mainLayout->addWidget(functionSelect);
    mainLayout->addWidget(inputLabel);
    mainLayout->addWidget(input);
    mainLayout->addWidget(keyLabel);
    mainLayout->addLayout(keyGenLayout);
    mainLayout->addWidget(outputLabel);
    mainLayout->addWidget(output);
    mainLayout->addLayout(butLayout);

    setLayout(mainLayout);
    readSettings();

    connect(functionSelect, SIGNAL(activated(QString)), this, SLOT(selectFun()));

}

void Window::selectFun()
{
    conv = new Conversion();
    hash = new Hashes();
    encry = new Encryption();

    functions fun = functions(functionSelect->currentIndex());

    if (fun != separator && fun != separator1 && fun != separator2) // Separator position
    {
        if (fun > separator1 && fun < separator2)
        {
            key->setReadOnly(false);
            generateKeyBut->setEnabled(true);

            if (key->text().isEmpty())
            {
                output->setText("Please write the key.");
                return;
            }
        }
        else
        {
            //key->clear();
            key->setReadOnly(true);
            generateKeyBut->setEnabled(false);
        }

        if (!input->toPlainText().isEmpty())
        {
            string msg;

            switch (fun)
            {
            case separator:
                break;
            case Adler32:
                msg = hash->Adler32Function(input->toPlainText());
                break;
            case CRC32:
                msg = hash->Crc32Function(input->toPlainText());
                break;
            case MD2:
                msg = hash->Md2Function(input->toPlainText());
                break;
            case MD4:
                msg = hash->Md4Function(input->toPlainText());
                break;
            case MD5:
                msg = hash->Md5Function(input->toPlainText());
                break;
            case RIPEMD128:
                msg = hash->Ripemd128Function(input->toPlainText());
                break;
            case RIPEMD160:
                msg = hash->Ripemd160Function(input->toPlainText());
                break;
            case RIPEMD320:
                msg = hash->Ripemd320Function(input->toPlainText());
                break;
            case SHA1:
                msg = hash->Sha1Function(input->toPlainText());
                break;
            case SHA224:
                msg = hash->Sha224Function(input->toPlainText());
                break;
            case SHA256:
                msg = hash->Sha256Function(input->toPlainText());
                break;
            case SHA384:
                msg = hash->Sha384Function(input->toPlainText());
                break;
            case SHA512:
                msg = hash->Sha512Function(input->toPlainText());
                break;
            case Tiger:
                msg = hash->TigerFunction(input->toPlainText());
                break;
            case Whirlpool:
                msg = hash->WhirlpoolFunction(input->toPlainText());
                break;
            case separator1:
                break;
            case AES:
                msg = encry->encryption(key->text(), input->toPlainText(), "AES", true);
                break;
            case AES_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "AES", false);
                break;
            case Blowfish:
                msg = encry->encryption(key->text(), input->toPlainText(), "Blowfish", true);
                break;
                // FIXME : StreamTransformationFilter: invalid PKCS #7 block padding found - FIXED
            case Blowfish_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Blowfish", false);
                break;
            case Camellia:
                msg = encry->encryption(key->text(), input->toPlainText(), "Camellia", true);
                break;
            case Camellia_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Camellia", false);
                break;
            case CAST128:
                msg = encry->encryption(key->text(), input->toPlainText(), "CAST128", true);
                break;
            case CAST128_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "CAST128", false);
                break;
            case CAST256:
                msg = encry->encryption(key->text(), input->toPlainText(), "CAST256", true);
                break;
            case CAST256_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "CAST256", false);
                break;
            case DES:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES", true);
                break;
            case DES_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES", false);
                break;
            case DES_EDE2:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES_EDE2", true);
                break;
            case DES_EDE2_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES_EDE2", false);
                break;
            case DES_EDE3:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES_EDE3", true);
                break;
            case DES_EDE3_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES_EDE3", false);
                break;
            case DES_XEX3:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES_XEX3", true);
                break;
            case DES_XEX3_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "DES_XEX3", false);
                break;
            case GOST:
                msg = encry->encryption(key->text(), input->toPlainText(), "GOST", true);
                break;
            case GOST_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "GOST", false);
                break;
            case IDEA:
                msg = encry->encryption(key->text(), input->toPlainText(), "IDEA", true);
                break;
            case IDEA_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "IDEA", false);
                break;
            case MARS:
                msg = encry->encryption(key->text(), input->toPlainText(), "MARS", true);
                break;
            case MARS_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "MARS", false);
                break;
            case Panama:
                msg = encry->encryption(key->text(), input->toPlainText(), "Panama", true);
                break;
            case Panama_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Panama", false);
                break;
            case RC2:
                msg = encry->encryption(key->text(), input->toPlainText(), "RC2", true);
                break;
            case RC2_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "RC2", false);
                break;
            case RC5:
                msg = encry->encryption(key->text(), input->toPlainText(), "RC5", true);
                break;
            case RC5_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "RC5", false);
                break;
            case RC6:
                msg = encry->encryption(key->text(), input->toPlainText(), "RC6", true);
                break;
            case RC6_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "RC6", false);
                break;
            case SAFER_K:
                msg = encry->encryption(key->text(), input->toPlainText(), "SAFER_K", true);
                break;
            case SAFER_K_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SAFER_K", false);
                break;
            case SAFER_SK:
                msg = encry->encryption(key->text(), input->toPlainText(), "SAFER_SK", true);
                break;
            case SAFER_SK_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SAFER_SK", false);
                break;
            case Salsa20:
                msg = encry->encryption(key->text(), input->toPlainText(), "Salsa20", true);
                break;
            case Salsa20_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Salsa20", false);
                break;
            case SEAL:
                msg = encry->encryption(key->text(), input->toPlainText(), "SEAL", true);
                break;
            case SEAL_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SEAL", false);
                break;
			case SEED:
                msg = encry->encryption(key->text(), input->toPlainText(), "SEED", true);
                break;
            case SEED_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SEED", false);
                break;
            case Serpent:
                msg = encry->encryption(key->text(), input->toPlainText(), "Serpent", true);
                break;
            case Serpent_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Serpent", false);
                break;
            case SHACAL2:
                msg = encry->encryption(key->text(), input->toPlainText(), "SHACAL2", true);
                break;
            case SHACAL2_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SHACAL2", false);
                break;
            case SHARK:
                msg = encry->encryption(key->text(), input->toPlainText(), "SHARK", true);
                break;
            case SHARK_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SHARK", false);
                break;
            case SKIPJACK:
                msg = encry->encryption(key->text(), input->toPlainText(), "SKIPJACK", true);
                break;
            case SKIPJACK_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "SKIPJACK", false);
                break;
            case Sosemanuk:
                msg = encry->encryption(key->text(), input->toPlainText(), "Sosemanuk", true);
                break;
            case Sosemanuk_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Sosemanuk", false);
                break;
            case Square:
                msg = encry->encryption(key->text(), input->toPlainText(), "Square", true);
                break;
            case Square_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Square", false);
                break;
            case TEA:
                msg = encry->encryption(key->text(), input->toPlainText(), "TEA", true);
                break;
            case TEA_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "TEA", false);
                break;
            case ThreeWay:
                msg = encry->encryption(key->text(), input->toPlainText(), "ThreeWay", true);
                break;
            case ThreeWay_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "ThreeWay", false);
                break;
            case Twofish:
                msg = encry->encryption(key->text(), input->toPlainText(), "Twofish", true);
                break;
            case Twofish_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "Twofish", false);
                break;
            case XSalsa20:
                msg = encry->encryption(key->text(), input->toPlainText(), "XSalsa20", true);
                break;
            case XSalsa20_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "XSalsa20", false);
                break;
            case XTEA:
                msg = encry->encryption(key->text(), input->toPlainText(), "XTEA", true);
                break;
            case XTEA_D:
                msg = encry->encryption(key->text(), input->toPlainText(), "XTEA", false);
                break;
            case separator2:
                break;
            case Base32Encode:
                msg = conv->Base32EncodeFun(input->toPlainText());
                break;
            case Base32Decode:
                msg = conv->Base32DecodeFun(input->toPlainText());
                break;
            case Base64Encode:
                msg = conv->Base64EncodeFun(input->toPlainText());
                break;
            case Base64Decode:
                msg = conv->Base64DecodeFun(input->toPlainText());
                break;
            case HexEncode:
                msg = conv->HexEncodeFun(input->toPlainText());
                break;
            case HexDecode:
                msg = conv->HexDecodeFun(input->toPlainText());
                break;
			case LeetSpeakEncode:
                msg = conv->LeetSpeakEncodeFun(input->toPlainText());
				break;
			case LeetSpeakDecode:
                msg = conv->LeetSpeakDecodeFun(input->toPlainText());
				break;
			case Reverse:
                msg = conv->ReverseFun(input->toPlainText());
				break;
            case Rot13Encode:
                msg = conv->Rot13EncodeFun(input->toPlainText());
                break;
            case URLEncode:
                msg = conv->UrlEncodeString(input->toPlainText());
                break;
            case URLDecode:
                msg = conv->UrlDecodeString(input->toPlainText());
                break;
            case UUEncode:
                msg = conv->UUEncodeString(input->toPlainText());
                break;
            case UUDecode:
                msg = conv->UUDecodeString(input->toPlainText());
                break;
            }
            if (lowercase->isChecked())
                output->setText(QString::fromStdString(msg).toLower());
            else
                output->setText(QString::fromStdString(msg));

            inputsEnable(true);
        }
        else
        {
            output->setText("Please write something.");
            inputsEnable(false);
        }
    }
    else
    {
        output->setText("Please select a function from the drop down box.");
        inputsEnable(false);

        //key->clear();
        key->setReadOnly(true);
        generateKeyBut->setEnabled(false);
    }
}

void Window::clear()
{
    input->clear();
    key->clear();
    output->clear();
}

void Window::swap()
{
    QString help = input->toPlainText();
    input->setText(output->toPlainText());
    output->setText(help);
}

void Window::copy()
{
    output->selectAll();
    output->copy();
}

void Window::about()
{
    aboutDialog = new About(this);
    aboutDialog->exec();
}

void Window::inputsEnable(bool stat)
{
    clearBut->setEnabled(stat);
    swapBut->setEnabled(stat);
    copyBut->setEnabled(stat);
}

void Window::stayOnTop()
{
    QPoint cur = mapToGlobal( QPoint(0, 0) );
    if (windowStaysOnTop->isChecked())
        setWindowFlags( windowFlags() | Qt::WindowStaysOnTopHint );
    else
        setWindowFlags( windowFlags() & (~ Qt::WindowStaysOnTopHint) );
    move( cur );
    show();
}

void Window::bruteForceSlot()
{
    bruteForceDialog = new BruteForce(this);

    if (bruteForceDialog->exec())
    {
        QSettings settings(tr("Qrypto", "Qt apps"));

        settings.setValue("BruteForce/Uppercase", bruteForceDialog->upperCase->isChecked());
        settings.setValue("BruteForce/Lowercase", bruteForceDialog->lowerCase->isChecked());
        settings.setValue("BruteForce/Numbers", bruteForceDialog->numbers->isChecked());
        settings.setValue("BruteForce/SpecialChar", bruteForceDialog->speChar->isChecked());
        settings.setValue("BruteForce/Customized", bruteForceDialog->customBox->isChecked());
        settings.setValue("BruteForce/maxKeySize", bruteForceDialog->maxKeySize->value());
    }
}

void Window::historySlot()
{
    historyWindow = new HistoryWindow(this);
    QPoint p = pos();
    p.rx() += 480;

    connect(historyWindow, SIGNAL(grabSignal(QString)), this, SLOT(grabSignal(QString)));

    historyWindow->move(p);
    historyWindow->setFixedSize(400, 480);
    historyWindow->show();
}

void Window::grabSignal(QString fun)
{
    int currentFun = functionSelect->currentIndex();

    if (!input->toPlainText().isEmpty())
    {
        QString finalText;
        if (!historyWindow->textEdit->toPlainText().isEmpty())
            finalText += historyWindow->textEdit->toPlainText();

        if (fun == "Input")
        {
            if (currentFun > 16 && currentFun < 69)
                finalText += "\nInput: " + input->toPlainText() + "\nKey: " + key->text() + "\n";
            else
                finalText += "\nInput: " + input->toPlainText() + "\n";
        }

        else if (currentFun != 0 && currentFun != 16 && currentFun != 69)
        {
            if (fun == "Output")
                finalText += "\nOutput: " + output->toPlainText() + "\n";

            else if (fun == "All")
            {
                if (currentFun > 16 && currentFun < 69)
                    finalText += "\nInput: " + input->toPlainText() + "\nKey: " + key->text() + "\nOutput: " + output->toPlainText() + "\n";
                else
                    finalText += "\nInput: " + input->toPlainText() + "\nOutput: " + output->toPlainText() + "\n";
            }
        }

        historyWindow->textEdit->setText(finalText);
        historyWindow->clear->setEnabled(true);
    }
}

void Window::generateKeyOptSlot()
{
    genKeyDialog = new GenerateKey(this);

    if (genKeyDialog->exec())
    {
        QSettings settings(tr("Qrypto", "Qt apps"));

        settings.setValue("GenerateKey/Uppercase", genKeyDialog->upperCase->isChecked());
        settings.setValue("GenerateKey/Lowercase", genKeyDialog->lowerCase->isChecked());
        settings.setValue("GenerateKey/Numbers", genKeyDialog->numbers->isChecked());
        settings.setValue("GenerateKey/SpecialChar", genKeyDialog->speChar->isChecked());
        settings.setValue("GenerateKey/Lenght", genKeyDialog->lenth->value());
    }
}

void Window::generateKeyFunSlot()
{
    if (!key->isReadOnly())
    {
        QString keyGenerated;
        QString keyType;
        int max, intGen;
        qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));

        genKeyDialog = new GenerateKey(this);

        if (genKeyDialog->upperCase->isChecked())
            keyType += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        if (genKeyDialog->lowerCase->isChecked())
            keyType += "abcdefghijklmnopqrstuvwxyz";

        if (genKeyDialog->numbers->isChecked())
            keyType += "0123456789";

        if (genKeyDialog->speChar->isChecked())
            keyType += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        if (!keyType.isEmpty())
        {
            max = keyType.size();

            for (int i = 0; i < genKeyDialog->lenth->value() ; i++)
            {
                intGen = (qrand() % max);
                keyGenerated[i] = keyType[intGen];
            }

            key->setText(keyGenerated);
        }

        else
        {
            QMessageBox::critical(this, "Error", "Please select the Aplphabet to use from the Generate Key Options");
            return;
        }

    }
    else
        output->setText("Please select an encryption function first");
}

GenerateKey::GenerateKey(QWidget *parent) : QDialog(parent)
{
    upperCase = new QCheckBox("Uppercase Aplphabet");
    lowerCase = new QCheckBox("Lowercase Aplphabet");
    numbers = new QCheckBox("Numbers");
    speChar = new QCheckBox("Special Characteres");

    lenthLabel = new QLabel(tr("Lenth of key:"));
    lenth = new QSpinBox;
    lenth->setMaximum(32);
    lenth->setMinimum(1);
    lenth->setValue(12);

    QGridLayout *layoutOptions = new QGridLayout;
    layoutOptions->addWidget(upperCase, 0, 0);
    layoutOptions->addWidget(lowerCase, 1, 0);
    layoutOptions->addWidget(numbers, 0, 1);
    layoutOptions->addWidget(speChar, 1, 1);
    layoutOptions->addWidget(lenthLabel, 2, 0);
    layoutOptions->addWidget(lenth, 2, 1);

    okButton = new QPushButton(QIcon(":/data/ok.png"), tr("Apply"));
    connect(okButton, SIGNAL(clicked()), this, SLOT(accept()));
    cancelButton = new QPushButton(QIcon(":/data/cancel.png"), tr("Cancel"));
    connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->setAlignment(Qt::AlignRight);

    QVBoxLayout *layout = new QVBoxLayout();
    layout->addLayout(layoutOptions);
    layout->addLayout(buttonLayout);

    QSettings settings(tr("Qrypto", "Qt apps"));

    upperCase->setChecked(settings.value("GenerateKey/Uppercase", true).toBool());
    lowerCase->setChecked(settings.value("GenerateKey/Lowercase").toBool());
    numbers->setChecked(settings.value("GenerateKey/Numbers", true).toBool());
    speChar->setChecked(settings.value("GenerateKey/SpecialChar").toBool());
    lenth->setValue(settings.value("GenerateKey/Lenght", 12).toInt());

    setLayout(layout);
    setWindowTitle(tr("Generate Key Options"));
}

void Window::readSettings()
{
    QSettings settings(tr("Qrypto", "Qt apps"));

    lowercase->setChecked(settings.value("LowerCase").toBool());
    windowStaysOnTop->setChecked(settings.value("StayOnTop").toBool());
    QPoint pos = settings.value("pos", QPoint(400, 130)).toPoint();

    stayOnTop();
    setWindowTitle("Qrypto");
    setWindowIcon(QIcon(":/data/qrypto.png"));
    setFixedSize(470, 480);
    move(pos);
}

void Window::writeSettings()
{
    QSettings settings(tr("Qrypto", "Qt apps"));

    settings.setValue("LowerCase", lowercase->isChecked());
    settings.setValue("StayOnTop", windowStaysOnTop->isChecked());
    settings.setValue("pos", pos());
}

void Window::closeEvent(QCloseEvent *event)
{
    writeSettings();
    event->accept();
}
