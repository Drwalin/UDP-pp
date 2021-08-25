/*
 *  This file is a part of simple C++ crossplatform UDP Wrapper
 *  Copyright (C) 2021 Marek Zalewski aka Drwalin
 *
 *  This is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if !defined(OS_WINDOWS) && !defined(OS_LINUX)

# if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#  define OS_WINDOWS
#  define OS_WIN
# endif

# if defined(__unix__) || defined(__unix) || defined(unix)
#  define OS_LINUX
#  define OS_LIN
#  define OS_NIX
# endif

# if !defined(OS_WINDOWS) && !defined(OS_LINUX)
#  error Invalid OS: not a Windows nor Linux
# endif

#endif
