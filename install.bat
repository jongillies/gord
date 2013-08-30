@echo off

REM Copyright 2010 Google Inc.
REM 
REM Licensed under the Apache License, Version 2.0 (the "License");
REM you may not use this file except in compliance with the License.
REM You may obtain a copy of the License at
REM 
REM     http://www.apache.org/licenses/LICENSE-2.0
REM
REM Unless required by applicable law or agreed to in writing, software
REM distributed under the License is distributed on an "AS IS" BASIS,
REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM See the License for the specific language governing permissions and
REM limitations under the License.

SET SERVICE_NAME=GORD
SET PYTHON=C:\python24\python.exe

IF NOT EXIST %PYTHON% GOTO install_python

sc query %SERVICE_NAME% | find "SERVICE_NAME" 2>&1 >nul
IF %ERRORLEVEL% == 0 GOTO already_exists

:new_install
echo Installing %SERVICE_NAME%
run.bat install
GOTO done

:already_exists
echo %SERVICE_NAME% is already installed.
GOTO done

:install_python
echo Please install Python 2.4 in %PYTHON%
goto done

:done
