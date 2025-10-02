#include "mainwindow.h"
#include <QtWidgets/qbuttongroup.h>
#include <QtWidgets/qpushbutton.h>
#include <QtWidgets/qradiobutton.h>
#include "./ui_mainwindow.h"
#include "cryptopp/base64.h"
#include "cryptopp/hex.h"

using namespace CryptoPP;
MainWindow::MainWindow(
    QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , encodeTypeGroup(new QButtonGroup)
    , encodeCodeMethodGroup(new QButtonGroup)
{
    ui->setupUi(this);
    initEncodeDecode();

    hexencode["Raw"] = [](const QString &in) -> QString {
        return in;
    };

    hexencode["Base64"] = [](const QString &in) -> QString {
        std::string output;
        StringSource ss(in.toStdString().c_str(),
                        true,
                        new Base64Encoder(new StringSink(output),
                                          false // 不插入换行符
                                          ));

        return QString::fromStdString(output);
    };

    hexdecode["Base64"] = [](const QString &in) -> SecByteBlock {
        std::string output;
        StringSource ss(in.toStdString().c_str(), true, new Base64Decoder(new StringSink(output)));
        return SecByteBlock(reinterpret_cast<const byte*>(output.data()), output.size());
    };

    hexencode["Base64Url"] = [](const QString &in) -> QString {
        std::string output;
        StringSource ss(in.toStdString().c_str(),
                        true,
                        new Base64URLEncoder(new StringSink(output),
                                          false // 不插入换行符
                                          ));

        return QString::fromStdString(output);
    };
    
    hexdecode["Base64Url"] = [](const QString &in) -> SecByteBlock {
        std::string output;
        StringSource ss(in.toStdString().c_str(), true, new Base64URLDecoder(new StringSink(output)));
        return SecByteBlock(reinterpret_cast<const byte*>(output.data()), output.size());
    };

    hexencode["Hex"] = [](const QString &in) -> QString {
        std::string output;
        StringSource ss(in.toStdString().c_str(),
                        true,
                        new HexEncoder(new StringSink(output),
                                       false // 不插入换行符
                                       ));

        return QString::fromStdString(output);
    };
    hexdecode["Hex"] =[](const QString &in) -> SecByteBlock {
        std::string output;
        StringSource ss(in.toStdString().c_str(), true, new HexDecoder(new StringSink(output)));
        return SecByteBlock(reinterpret_cast<const byte*>(output.data()), output.size());
    };


    init_symmetric();

}


MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::showLogs(QString method , QString info)
{
    //  添加日期时间
    QDateTime currentDateTime = QDateTime::currentDateTime();
    QString dateTimeString = currentDateTime.toString("yyyy-MM-dd HH:mm:ss");
    ui->outlogs->appendPlainText(QString("[%1][%2] %3").arg(dateTimeString).arg(method).arg(info));
    ui->outlogs->verticalScrollBar()->setValue(ui->outlogs->verticalScrollBar()->maximum());


}

