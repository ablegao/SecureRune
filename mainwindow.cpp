#include "mainwindow.h"
#include <QtWidgets/qbuttongroup.h>
#include <QtWidgets/qpushbutton.h>
#include <QtWidgets/qradiobutton.h>
#include "./ui_mainwindow.h"
#include "cryptopp/base64.h"
#include "cryptopp/hex.h"
#include "secblock.h"

using namespace CryptoPP;

// definition of static instance pointer
MainWindow *MainWindow::s_instance = nullptr;

MainWindow *MainWindow::instance()
{
    return s_instance;
}
MainWindow::MainWindow(
    QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , encodeTypeGroup(new QButtonGroup)
    , encodeCodeMethodGroup(new QButtonGroup)
{
    ui->setupUi(this);
    // register instance for global access
    MainWindow::s_instance = this;
    initEncodeDecode();

    hexencode["Raw"] = [](const SecByteBlock &in) -> QString {
        // Treat the bytes as UTF-8 text when using Raw -> display as QString
        return QString::fromUtf8(reinterpret_cast<const char*>(in.data()), static_cast<int>(in.size()));
    };

    hexdecode["Raw"] = [](const QString &in) -> SecByteBlock {
        QByteArray ba = in.toUtf8();
        return SecByteBlock(reinterpret_cast<const byte*>(ba.constData()), static_cast<size_t>(ba.size()));
    };

    hexencode["Base64"] = [](const SecByteBlock &in) -> QString {
        std::string output;
        StringSource ss(in.data(), in.size(),
                        true,
                        new Base64Encoder(new StringSink(output),
                                          false // don't insert line breaks
                                          ));

        return QString::fromStdString(output);
    };

    hexdecode["Base64"] = [](const QString &in) -> SecByteBlock {
        std::string input = in.toStdString();
        std::string output;
        StringSource ss(input, true, new Base64Decoder(new StringSink(output)));
        return SecByteBlock(reinterpret_cast<const byte*>(output.data()), output.size());
    };

    hexencode["Base64Url"] = [](const SecByteBlock &in) -> QString {
        std::string output;
        StringSource ss(in.data(), in.size(),
                        true,
                        new Base64URLEncoder(new StringSink(output),
                                          false // don't insert line breaks
                                          ));

        return QString::fromStdString(output);
    };
    
    hexdecode["Base64Url"] = [](const QString &in) -> SecByteBlock {
        std::string input = in.toStdString();
        std::string output;
        StringSource ss(input, true, new Base64URLDecoder(new StringSink(output)));
        return SecByteBlock(reinterpret_cast<const byte*>(output.data()), output.size());
    };

    hexencode["Hex"] = [](const SecByteBlock &in) -> QString {
        std::string output;
        StringSource ss(in.data(), in.size(), true, new HexEncoder(new StringSink(output), false));
        return QString::fromStdString(output);
    };
    hexdecode["Hex"] =[](const QString &in) -> SecByteBlock {
        std::string input = in.toStdString();
        std::string output;
        StringSource ss(input, true, new HexDecoder(new StringSink(output)));
        return SecByteBlock(reinterpret_cast<const byte*>(output.data()), output.size());
    };

    init_symmetric();

}


MainWindow::~MainWindow()
{
    // unregister instance
    MainWindow::s_instance = nullptr;
    delete ui;
}


// 在 mainwindow.h 里添加（示例）：


// 保留原来的简便函数（不改动现有使用）
void MainWindow::showLogs(QString method , QString info)
{
    QDateTime currentDateTime = QDateTime::currentDateTime();
    QString dateTimeString = currentDateTime.toString("yyyy-MM-dd HH:mm:ss");
    ui->outlogs->appendPlainText(QString("[%1][%2] %3").arg(dateTimeString).arg(method).arg(info));
    ui->outlogs->verticalScrollBar()->setValue(ui->outlogs->verticalScrollBar()->maximum());
}

