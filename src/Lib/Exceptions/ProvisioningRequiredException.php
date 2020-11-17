<?php
/***********************************************
* File      :   ProvisioningRequiredException.php
* Project   :   Z-Push
* Descr     :   Exception announcing to the mobile that a
*               provisioning request is required
*
* Created   :   06.02.2012
*
* Copyright 2007 - 2016 Zarafa Deutschland GmbH
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License, version 3,
* as published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Consult LICENSE file for details
************************************************/
namespace ZPush\Lib\Exceptions;

class ProvisioningRequiredException extends HTTPReturnCodeException{

    protected $defaultLogLevel = LOGLEVEL_INFO;
    protected $httpReturnCode = HTTP_CODE_449;
    protected $httpReturnMessage = 'Retry after sending a PROVISION command';

}