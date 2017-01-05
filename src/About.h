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


#ifndef HEADER_ABOUT
#define HEADER_ABOUT

#include <QtGui>


class About : public QDialog
{

public :
    About(QWidget *parent=0);

private :
    QPushButton *cancelButton;
    QTabWidget *tabs;
    QWidget *page1;
    QWidget *page2;
    QWidget *page3;
    QLabel *description;
    QLabel *authors;
    QLabel *license;
    QLabel *logoText;
    QLabel *logoImage;
};

#endif
