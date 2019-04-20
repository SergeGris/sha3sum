
/* Program name management.
   Copyright (C) 2001-2004, 2006, 2009-2018 Free Software Foundation, Inc.
   Written by Bruno Haible <bruno@clisp.org>, 2001.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#ifndef _PROGNAME_H
#define _PROGNAME_H

/* Programs using this file should do the following in main():
   set_program_name(argv[0]);
 */

#ifdef __cplusplus
extern "C"
{
#endif

/* String containing name the program is called with.  */
extern const char *program_name;

/* Set program_name, based on argv[0].
   argv0 must be a string allocated with indefinite extent, and must not be
   modified after this call.  */
extern void set_program_name(const char *argv0);

#ifdef __cplusplus
}
#endif

#endif /* _PROGNAME_H */
