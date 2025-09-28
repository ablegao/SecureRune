#include "mainwindow.h"
#include <QtWidgets/qbuttongroup.h>
#include <QtWidgets/qpushbutton.h>
#include <QtWidgets/qradiobutton.h>
#include "./ui_mainwindow.h"
#include <iostream>
#include <ostream>
#include "cryptopp/base64.h"



void MainWindow::initEncodeDecode()
{
    encodeTypeGroup->addButton(ui->code_radio_base16);
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

    // encodeCustomAlphabetMap

    connect(encodeTypeGroup,
            &QButtonGroup::buttonClicked,
            this,
            &MainWindow::on_encodetype_radio_changed);

    connect(ui->code_enter,
            &QPushButton::pressed,
            this,
            &MainWindow::on_encode_input_plaintext_textChanged);


    encodeCodeMethodGroup->addButton(ui->encodeTypeA);
    encodeCodeMethodGroup->addButton(ui->encodeTypeB);
}

void MainWindow::on_encode_input_plaintext_textChanged()
{
    if (encodeTypeGroup->checkedButton())
    {

        std::cout << ui->encode_input_plaintext->toPlainText().toStdString()
        << encodeTypeGroup->checkedButton()->text().toStdString() << std::endl;
    }
}

void MainWindow::on_encodetype_radio_changed()
{
    std::cout << "encodeType RadioChanged " << encodeTypeGroup->checkedButton()->text().toStdString() << std::endl;

}
