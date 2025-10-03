#pragma once

#include <QWidget>
#include <QLoggingCategory>
#include <QPoint>

class PartyManager;
class QTableView;
class QStandardItemModel;
class Bot;
class QStandardItem;

Q_DECLARE_LOGGING_CATEGORY(logPartyWidget)

class PartyWidget : public QWidget
{
    Q_OBJECT
   public:
    explicit PartyWidget(PartyManager* partyManager, QWidget* parent = nullptr);
    ~PartyWidget();

   public slots:
    void forceRefresh();

   private slots:
    void refreshPartyView();
    void onShowContextMenu(const QPoint& pos);

   private:
    Bot* getBotFromIndex(const QModelIndex& index) const;

    PartyManager* m_partyManager;
    QTableView* m_membersTable;
    QStandardItemModel* m_tableModel;
};