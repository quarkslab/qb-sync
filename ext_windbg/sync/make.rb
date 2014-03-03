#
# Copyright (C) 2012-2014, Quarkslab.
#
# This file is part of qb-sync.
#
# qb-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#!/usr/bin/ruby
# encoding: ASCII-8BIT

TMP = 'tmp.bat'
BUILD = 'fre'
DDKPATH = 'C:\WinDDK\7600.16385.1'
ARCHS = ['x86', 'x64']
TARGETS = ['WXP', 'WIN7']

# grab your panties 
abort("\n\nShit out of luck") unless File.exists? DDKPATH

# disable oacr
File.open("#{DDKPATH}\\bin\\setenv.bat",'r'){|ifd| 
    File.open('setenv.bat','w'){|ofd| ofd << ifd.read().sub!(/_RunOacr=TRUE/, '_RunOacr=FALSE')}
} unless File.exists? 'setenv.bat'

# build all
ARCHS.product(TARGETS).each{|arch, target|
    puts "\n\n[+] building #{BUILD} #{arch} #{target}"
    File.open(TMP, 'w'){|fd|
        fd << <<EOS
set SYNCDIR=%CD%
call setenv.bat #{DDKPATH} #{BUILD} #{arch} #{target}
chdir /d %SYNCDIR%
set DBGSDK_INC_PATH=#{DDKPATH}\\Debuggers\\sdk\\inc
set DBGSDK_LIB_PATH=#{DDKPATH}\\Debuggers\\sdk\\lib
set DBGLIB_LIB_PATH=#{DDKPATH}\\Debuggers\\sdk\\lib
build -cZMg
EOS
    }
    system("cmd.exe /c #{TMP}")
    abort("\n\nToo drunk to fuck, eh?") unless Dir.glob("*.err").empty?
}

# clean
File.unlink(TMP)
Dir.glob('build*.log').to_a.each{|f| File.unlink(f)}
