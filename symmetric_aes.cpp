#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QtWidgets/qbuttongroup.h>
#include <string>
#include "modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"

using namespace CryptoPP;


// Generic helper: Encrypt using an Encryptor type. If UsesIV is true, call SetKeyWithIV, else SetKey.
template <typename Encryptor, bool UsesIV>
static std::string aes_encrypt_helper(const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding = StreamTransformationFilter::PKCS_PADDING)
{
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Invalid AES key size. Must be 16, 24, or 32 bytes.");
    }
    if constexpr (UsesIV) {
        if (iv.size() != AES::BLOCKSIZE) {
            throw std::runtime_error("Invalid AES IV size. Must be 16 bytes.");
        }
    }

    Encryptor encryptor;
    if constexpr (UsesIV) {
        encryptor.SetKeyWithIV(key, key.size(),
                               iv, iv.size());
    } else {
        encryptor.SetKey(key, key.size());
    }

    std::string cipher;
    StringSource ss(in, true,
                    new StreamTransformationFilter(encryptor,
                                                   new StringSink(cipher),
                                                   padding));
    return cipher;
}

template <typename Decryptor, bool UsesIV>
static std::string aes_decrypt_helper(const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding = StreamTransformationFilter::PKCS_PADDING)
{
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Invalid AES key size. Must be 16, 24, or 32 bytes.");
    }
    if constexpr (UsesIV) {
        if (iv.size() != AES::BLOCKSIZE) {
            throw std::runtime_error("Invalid AES IV size. Must be 16 bytes.");
        }
    }

    Decryptor decryptor;
    if constexpr (UsesIV) {
        decryptor.SetKeyWithIV(key, key.size(),
                               iv, iv.size());
    } else {
        decryptor.SetKey(key, key.size());
    }

    std::string cipher;
    StringSource ss(in, true,
                    new StreamTransformationFilter(decryptor,
                                                   new StringSink(cipher),
                                                   padding));
    return cipher;
    ;
}


// (specific helpers removed) use aes_encrypt_helper<> above instead


void MainWindow::init_symmetric()
{
    symmetricChiphers << "DES"
                      << "3DES"
                      << "AES"
                      << "Rijndael"
                      << "SM4"
                      << "Blowfish"
                      << "Twofish"
                      << "Threefish-256"
                      << "Threefish-512"
                      << "Threefish-1024"
                      << "RC2"
                      << "RC5"
                      << "RC6"
                      << "Camellia"
                      << "CAST5"
                      << "CAST6"
                      << "ARIA"
                      << "Skipjack"
                      << "Tnepres"
                      << "Serpent"
                      << "DSTU7624"
                      << "Shacal2"
                      << "GOST28147"
                      << "GOST3412-2015"
                      << "Noekeon"
                      << "IDEA"
                      << "SEED"
                      << "TEA"
                      << "XTEA"
                      // coco2d encrypt
                      << "XXTEA"
                      << "XOR";

    ui->s_chipher->addItems(symmetricChiphers);

    symmetricModes << "CBC" << "ECB" << "CFB" << "OFB" << "CTR";
    //<< "GCM" << "CCM" << "EAX" << "OCB";
    ui->s_mode->addItems(symmetricModes);
    // 对应 Crypto++ 的填充方式如下：
    // "PKCS"        -> StreamTransformationFilter::PKCS_PADDING (PKCS#7)
    // "ISO10126"    -> Crypto++ 没有直接实现 ISO10126 填充
    // "ZeroByte"    -> StreamTransformationFilter::ZEROS_PADDING
    // "NoPadding"   -> StreamTransformationFilter::NO_PADDING
    // "TBC"         -> Crypto++ 没有直接实现 TBC 填充
    // "X923"        -> Crypto++ 没有直接实现 X9.23 填充
    // "ISO7816-4"   -> Crypto++ 没有直接实现 ISO7816-4 填充
    // "ISO10126-2"  -> Crypto++ 没有直接实现 ISO10126-2 填充
    symmetricPaddingMap["PKCS"] = StreamTransformationFilter::PKCS_PADDING;
    symmetricPaddingMap["ZeroByte"] = StreamTransformationFilter::ZEROS_PADDING;
    symmetricPaddingMap["NoPadding"] = StreamTransformationFilter::NO_PADDING;
    // 其它填充方式 Crypto++ 没有直接支持，如需使用需自定义实现
    // ui->s_padding->addItems(symmetricPaddings);
    // 循环 symmetricPaddingMap 的key 作为选项添加到 ui->s_padding
    for (const auto &paddingName : symmetricPaddingMap.keys()) {
        ui->s_padding->addItem(paddingName);
    }

    // ensure the QButtonGroup is constructed before use
    
    symmetricOutputFormatGroup = new QButtonGroup(this);
    symmetricOutputFormatGroup->addButton(ui->s_output_type_raw);
    symmetricOutputFormatGroup->addButton(ui->s_output_type_hex);
    symmetricOutputFormatGroup->addButton(ui->s_output_type_base64);
    symmetricOutputFormatGroup->addButton(ui->s_output_type_base64url);

    symmetricKeyFormatGroup = new QButtonGroup(this);
    symmetricKeyFormatGroup->addButton(ui->s_key_type_raw);
    symmetricKeyFormatGroup->addButton(ui->s_key_type_base64);
    symmetricKeyFormatGroup->addButton(ui->s_key_type_hex);
    symmetricIVFormatGroup = new QButtonGroup(this);
    symmetricIVFormatGroup->addButton(ui->s_iv_type_raw);
    symmetricIVFormatGroup->addButton(ui->s_iv_type_base64);
    symmetricIVFormatGroup->addButton(ui->s_iv_type_hex);

    // symmetricChiphersHandler["AES"] = [this](){ symmetric_aes_action(); };

    symmetricModesEncodeHandler["AES_CBC"] = [](const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding) -> std::string {
        return aes_encrypt_helper<CBC_Mode<AES>::Encryption, true>(in, key, iv, padding);
    };

    symmetricModesEncodeHandler["AES_ECB"] = [](const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding) -> std::string {
        return aes_encrypt_helper<ECB_Mode<AES>::Encryption, false>(in, key, iv, padding);
    };
    symmetricModesEncodeHandler["AES_CFB"] = [](const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding) -> std::string {
        return aes_encrypt_helper<CFB_Mode<AES>::Encryption, true>(in, key, iv, padding);
    };
    symmetricModesEncodeHandler["AES_OFB"] = [](const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding) -> std::string {
        return aes_encrypt_helper<OFB_Mode<AES>::Encryption, true>(in, key, iv, padding);
    };
    symmetricModesEncodeHandler["AES_CTR"] = [](const std::string &in, const SecByteBlock &key, const SecByteBlock &iv, StreamTransformationFilter::BlockPaddingScheme padding) -> std::string {
        return aes_encrypt_helper<CTR_Mode<AES>::Encryption, true>(in, key, iv, padding);
    };
    // symmetricModesEncodeHandler["AES_GCM"] = [](const std::string &in, const std::string &key, const std::string &iv) -> std::string {
    //     return aes_encrypt_helper<GCM<AES>::Encryption, true>(in, key, iv, StreamTransformationFilter::PKCS_PADDING);
    // };
    // symmetricModesEncodeHandler["AES_CCM"] = [](const std::string &in, const std::string &key, const std::string &iv, StreamTransformationFilter::BlockPaddingScheme padding) -> std::string {
    //     return aes_encrypt_helper<CCM<AES>::Encryption, true>(in, key, iv, padding);
    // };




    /*
    connect(symmetricOutputTypeGroup,&QButtonGroup::buttonPressed,[this](QAbstractButton* btn){
        if (btn == ui->s_output_type_raw) {
            qDebug() << "s_output_type_raw";
        } else if (btn == ui->s_output_type_hex) {
            qDebug() << "s_output_type_hex";
        } else if (btn == ui->s_output_type_base64) {
            qDebug() << "s_output_type_base64";
        }
     });*/
}

void MainWindow::on_btn_symmetric_run_released()
{
    // switch (ui->s_chipher->currentText().toStdString().c_str()) {
    // case "AES":
    //     break;
    // }
    // try{
        qDebug() << "symmetric_aes_action ";
        // QString mode = ui->s_mode->currentText();
        QString mode = QString("%1_%2").arg(ui->s_chipher->currentText(), ui->s_mode->currentText());


        if (symmetricModesEncodeHandler.contains(mode)) {
            // QString key = //ui->symmetric_key->toPlainText();
            SecByteBlock key = hexdecode[symmetricKeyFormatGroup->checkedButton()->text()](ui->symmetric_key->toPlainText());
            SecByteBlock iv = hexdecode[symmetricIVFormatGroup->checkedButton()->text()](ui->symmetric_iv->toPlainText());
            QString input = ui->symmetric_input->toPlainText();
            QString paddingStr = ui->s_padding->currentText();
            auto padding = symmetricPaddingMap.value(paddingStr, StreamTransformationFilter::PKCS_PADDING);

            try {
                std::string cipher = symmetricModesEncodeHandler[mode](input.toStdString(), key, iv, padding);
                // ui->symmetric_output->setPlainText(QString::fromStdString(cipher));
                // qDebug() << "Encryption successful." << cipher.size() << "bytes produced.";
                // 根据输出格式选择进行编码
                ui->symmetric_output->setPlainText(hexencode[symmetricOutputFormatGroup->checkedButton()->text()](QString::fromStdString(cipher)));


            } catch (const std::exception &e) {
                qDebug() << "Error during encryption: " << e.what();
                ui->symmetric_output->setPlainText(QString("Error: %1").arg(e.what()));
            }
        } else {
            qDebug() << "No handler for mode: " << mode;
        }
    // } catch (const std::exception &e) {
    //     qDebug() << "Error: " << e.what();
    // }
}


void MainWindow::symmetric_aes_action()
{
    
}


// void MainWindow::symmetric_aes_cbc()
// {
//     CBC_Mode<AES>::Encryption encryptor;
//     new StreamTransformationFilter(encryptor );

// }

