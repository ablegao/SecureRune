#include <QTest>

class TestCryptoppAes : public QObject
{
    Q_OBJECT
private slots:
    void testAesEcb();
};



void TestCryptoppAes::testAesEcb()
{
    QCOMPARE(1, 1);

}
