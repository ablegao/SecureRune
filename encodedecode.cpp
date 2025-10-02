#include "mainwindow.h"
#include <QtWidgets/qabstractbutton.h>
#include <QtWidgets/qbuttongroup.h>
#include <QtWidgets/qpushbutton.h>
#include <QtWidgets/qradiobutton.h>
#include "./ui_mainwindow.h"
#include <cstdio>
#include "cryptopp/base64.h"

using namespace CryptoPP;
// using namespace std;

void MainWindow::initEncodeDecode()
{
    encodeTypeGroup->addButton(ui->code_radio_hex);
    encodeTypeGroup->addButton(ui->code_radio_base32);
    encodeTypeGroup->addButton(ui->code_radio_base36);
    encodeTypeGroup->addButton(ui->code_radio_base58);
    encodeTypeGroup->addButton(ui->code_radio_base62);
    encodeTypeGroup->addButton(ui->code_radio_base64);
    encodeTypeGroup->addButton(ui->code_radio_base85);
    encodeTypeGroup->addButton(ui->code_radio_base91);
    encodeTypeGroup->addButton(ui->code_radio_urlbase64);
    encodeTypeGroup->addButton(ui->code_radio_url);
    encodeTypeGroup->addButton(ui->code_radio_binary);
    encodeTypeGroup->addButton(ui->code_radio_decimal);
    encodeTypeGroup->addButton(ui->code_radio_qctal);
    encodeTypeGroup->addButton(ui->code_radio_url);

    encodeTypeOptions << "Base64"
                      << "UrlBase64"
                      << "Base32"
                      << "Base36"
                      << "Base58"
                      << "Base62"
                      << "Base85"
                      << "Base91"
                      << "Hex"
                      << "Binary"
                      << "URL"
                      << "Decimal"
                      << "Octal"
                      << "Escape";

    encodeCustomAlphabetMap["Base64"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    encodeCustomAlphabetMap["UrlBase64"]= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    // encodeCustomAlphabetMap

    connect(encodeTypeGroup,
            &QButtonGroup::buttonClicked,
            this,
            &MainWindow::on_encodetype_radio_changed);




    encodeCodeMethodGroup->addButton(ui->encodeTypeA);
    encodeCodeMethodGroup->addButton(ui->encodeTypeB);
}
void MainWindow::on_code_enter_released()
{
    MainWindow::on_encode_input_plaintext_textChanged();
}



void MainWindow::on_encode_input_plaintext_textChanged()
{
    QAbstractButton *btn = encodeTypeGroup->checkedButton();
    if (btn)
    {
        qDebug() << "====================== \n INPUT:";

        qDebug() << ui->encode_input_plaintext->toPlainText();
        qDebug() << encodeCodeMethodGroup->checkedButton()->text();



        QString output;
        bool encode = encodeCodeMethodGroup->checkedButton()->text() == "Encode";
        switch (encodeTypeOptions.indexOf(btn->text())) {
        case 0:
            output = base64Code(ui->encode_input_plaintext->toPlainText(),
                                ui->encode_custom_alphabet->text(),
                                encode);
                break;
        case 1:
            output = urlBase64Code(ui->encode_input_plaintext->toPlainText(),
                                   ui->encode_custom_alphabet->text(),
                                   encode);


            break;
        case 2:
            break;
        }

        ui->encode_output_plaintext->setPlainText(output);
        showLogs(btn->text()+ encodeCodeMethodGroup->checkedButton()->text(),ui->encode_output_plaintext->toPlainText());
    }
}

void MainWindow::on_encodetype_radio_changed()
{
    QString val = encodeTypeGroup->checkedButton()->text();
    if (encodeCustomAlphabetMap.contains(val)) {
        ui->encode_custom_alphabet->setEnabled(true);
        ui->encode_custom_alphabet->setText(encodeCustomAlphabetMap[val]);
    } else {
        ui->encode_custom_alphabet->setEnabled(false);
    }
}


void MainWindow::on_encode_replace_method_released()
{
    if (ui->encode_output_plaintext->toPlainText().isEmpty()) {
        return;
    }
    if (encodeCodeMethodGroup->checkedButton() == ui->encodeTypeA) {
        ui->encodeTypeB->setChecked(true);
    } else {
        ui->encodeTypeA->setChecked(true);
    }
    QString temp = ui->encode_output_plaintext->toPlainText();
    ui->encode_input_plaintext->setPlainText(temp);
}


QString MainWindow::urlBase64Code(QString incode, QString customAlphabet, bool encode)
{
    try {
        std::string stdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string input = incode.toStdString();
        std::string output;
        if (encode) {
            
            // // 创建Base64编码器
            StringSource ss(input, true,
                            new Base64URLEncoder(
                                new StringSink(output),
                                false // 不插入换行符
                                )
                            );

            if (!customAlphabet.isEmpty() && customAlphabet.length() == 64 && stdAlphabet != customAlphabet.toStdString())
            {
                std::string customAlphabetStr = customAlphabet.toStdString();

                for (char &ch : output) {
                    size_t pos = stdAlphabet.find(ch);
                    if (pos != std::string::npos) {
                        ch = customAlphabetStr[pos];
                    }
                }
            }
            
        } else {
            // 解码模式
            // // 创建Base64解码器
            if (!customAlphabet.isEmpty() && customAlphabet.length() == 64 && stdAlphabet != customAlphabet.toStdString()) {
                std::string customAlphabetStr = customAlphabet.toStdString();
                for (char &ch : input) {
                    size_t pos = customAlphabetStr.find(ch);
                    if (pos != std::string::npos) {
                        ch = stdAlphabet[pos];
                    }
                }
            }
            StringSource ss(input, true,
                            new Base64URLDecoder(
                                new StringSink(output)
                                )
                            );
        }
        return QString::fromStdString(output);
    } catch (const std::exception& e) {
        // 处理异常，返回错误信息
        return QString("Error: %1").arg(e.what());
    } catch (...) {
        // 处理未知异常
        return QString("Unknown error occurred");
    }
}



QString MainWindow::base64Code(QString incode, QString customAlphabet, bool encode)
{
    try {
        std::string stdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string input = incode.toStdString();
        std::string output;
        if (encode) {

            // // 创建Base64编码器
            StringSource ss(input, true,
                            new Base64Encoder(
                                new StringSink(output),
                                false // 不插入换行符
                                )
                            );

            if (!customAlphabet.isEmpty() && customAlphabet.length() == 64 && stdAlphabet != customAlphabet.toStdString())
            {
                std::string customAlphabetStr = customAlphabet.toStdString();

                for (char &ch : output) {
                    size_t pos = stdAlphabet.find(ch);
                    if (pos != std::string::npos) {
                        ch = customAlphabetStr[pos];
                    }
                }
            }

        } else {
            qDebug() << " NOW DECODE";
            // 解码模式
            // // 创建Base64解码器
            if (!customAlphabet.isEmpty() && customAlphabet.length() == 64 && stdAlphabet != customAlphabet.toStdString()) {
                std::string customAlphabetStr = customAlphabet.toStdString();
                for (char &ch : input) {
                    size_t pos = customAlphabetStr.find(ch);
                    if (pos != std::string::npos) {
                        ch = stdAlphabet[pos];
                    }
                }
            }
            StringSource ss(input, true,
                            new Base64Decoder(
                                new StringSink(output)
                                )
                            );
        }
        return QString::fromStdString(output);
    } catch (const std::exception& e) {
        // 处理异常，返回错误信息
        return QString("Error: %1").arg(e.what());
    } catch (...) {
        // 处理未知异常
        return QString("Unknown error occurred");
    }
}
