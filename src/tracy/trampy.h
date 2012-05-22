/*
    This file is part of Tracy.

    Tracy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tracy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tracy.  If not, see <http://www.gnu.org/licenses/>.
*/
/* Trampy is Tracy's secure entry point that can be injected in
 * child processes.
 *
 * It performs a busy wait, non-stop performing a schedule yield.
 * This busy wait therefore should not use up much CPU time since the process
 * immediately stops execution upon starting. In theory this should result
 * in the tracer being given control of the child ASAP.
 */

/* This function returns a pointer indicating the position of the entry code. */
void *trampy_get_safe_entry(void);

/* This function retuns the code size in bytes.
 *
 * The entry point is not guaranteed to work unless at least this many
 * bytes are copied.
 */
size_t trampy_get_code_size(void);

