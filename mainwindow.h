#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtCore/qcontainerfwd.h>
#include <QtCore/qmap.h>
#include "cryptopp/filters.h"
#include <QMainWindow>
#include <QtWidgets>
using namespace CryptoPP;

QT_BEGIN_NAMESPACE
namespace Ui {

class MainWindow;

}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_encode_input_plaintext_textChanged();
    void on_encodetype_radio_changed();

    void on_encode_replace_method_released();

    void on_code_enter_released();

    void on_btn_symmetric_run_released();

    void on_s_iv_random_released();

private:
    Ui::MainWindow *ui;

    void showLogs(QString method , QString info);

    QMap<QString, std::function<CryptoPP::SecByteBlock(const QString &)>> hexdecode;
    QMap<QString, std::function<QString(const QString &)>> hexencode;

    // encode/decode
    QButtonGroup *encodeTypeGroup;
    QButtonGroup *encodeCodeMethodGroup;
    QMap<QString, QString> encodeCustomAlphabetMap;
    QStringList encodeTypeOptions;

    void initEncodeDecode();

    QString base64Code(QString in, QString customAlphabet, bool encode);
    QString urlBase64Code(QString in , QString customAlphabet,bool encode);

    // hex


    // Symmetric

    void init_symmetric();
    QStringList symmetricChiphers;
    QStringList symmetricModes;
    QButtonGroup *symmetricOutputFormatGroup;
    QButtonGroup *symmetricIVFormatGroup;
    QButtonGroup *symmetricKeyFormatGroup;
    // QStringList symmetricPaddings;
    QMap<QString,StreamTransformationFilter::BlockPaddingScheme> symmetricPaddingMap;

    // 定义一个名为 symmetricModesHandler 的QMap ,保存 类似 AES_CBC 为key , 值为一个函数指针 ,传参为 QString key , QString iv  ,返回值 SecByteBlock
    QMap<QString, std::function<std::string(const std::string &, const SecByteBlock &, const SecByteBlock & , StreamTransformationFilter::BlockPaddingScheme)>> symmetricModesEncodeHandler;
    // void symmetric_aes_cbc();

};
#endif // MAINWINDOW_H
