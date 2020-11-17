<?php
/***********************************************
* File      :   syncvalidatecert.php
* Project   :   Z-Push
* Descr     :   WBXML appointment entities that can be
*               parsed directly (as a stream) from WBXML.
*               It is automatically decoded
*               according to $mapping,
*               and the Sync WBXML mappings
*
* Created   :   08.11.2011
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
namespace ZPush\Lib\SyncObjects;

class SyncValidateCert extends SyncObject {
    public $certificatechain;
    public $certificates;
    public $checkCRL;
    public $Status;

    public function __construct() {
        $mapping = array (
            SYNC_VALIDATECERT_CERTIFICATECHAIN  => array (  self::STREAMER_VAR      => "certificatechain",
                                                            self::STREAMER_ARRAY    => SYNC_VALIDATECERT_CERTIFICATE),

            SYNC_VALIDATECERT_CERTIFICATES      => array (  self::STREAMER_VAR      => "certificates",
                                                            self::STREAMER_ARRAY    => SYNC_VALIDATECERT_CERTIFICATE),

            SYNC_VALIDATECERT_CHECKCRL          => array (  self::STREAMER_VAR      => "checkCRL"),

            SYNC_SETTINGS_PROP_STATUS           => array (  self::STREAMER_VAR      => "Status",
                                                            self::STREAMER_TYPE     => self::STREAMER_TYPE_IGNORE)
        );

        parent::__construct($mapping);
    }

}
