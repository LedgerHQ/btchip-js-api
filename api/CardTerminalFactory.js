/*
************************************************************************
Copyright (c) 2012 UBINITY SAS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*************************************************************************
*/

var CardTerminalFactory = Class.create({
	/** @lends CardTerminalFactory.prototype */
	
	/**
	 * @class Interface defining the interaction with the available Card Terminals for the system
	 * @constructs
	 */
	initialize: function() {
		throw "abstract class"; 
	},
	
	
	/**
	 * List the names of the available terminals
	 * This name can be used to build a CardTerminal for the current implementation
	 * @returns {Array} list of available terminals names
	 */
	list: function() {
	},
	
	/**
	 * Get the card terminal associated to the given name
	 * @param {String} name name card terminal name
	 * @param {String} [initOptions] initialization options associated to this terminal 
	 * @returns {CardTerminal} card terminal
	 */
	getCardTerminal: function(name, initOptions) {
	},
	
	/**
	 * List the names of all terminals which received a card inserted event since the last call
	 * @returns {Array} name of all found terminals
	 */
	waitInserted: function() {
	},
	
});

