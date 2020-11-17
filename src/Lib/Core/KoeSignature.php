<?php
/***********************************************
 * File      :   KoeSignature.php
 * Project   :   Z-Push
 * Descr     :   Helper class holding a signature.
 *
 * Created   :   06.02.2017
 *
 * Copyright 2007 - 2017 Zarafa Deutschland GmbH
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
 *************************************************/
namespace ZPush\Lib\Core;

class KoeSignature {
	public $id;
	public $name;
	public $content;
	public $isHTML;

	/**
	 * Creates a new KoeSignature object from a data array.
	 *
	 * @param string $id
	 * @param array $data
	 *
	 * @access public
	 * @return KoeSignature
	 */
	public static function GetSignatureFromArray($id, array $data) {
		$sig = new KoeSignature();
		$sig->id = $id;
		$sig->name = $data['name'];
		$sig->content = $data['content'];
		$sig->isHTML = (bool) $data['isHTML'];
		return $sig;
	}
}