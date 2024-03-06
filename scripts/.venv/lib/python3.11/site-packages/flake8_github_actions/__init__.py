#!/usr/bin/env python3
#
#  __init__.py
"""
GitHub Actions integration for flake8.
"""
#
#  Copyright © 2020 Dominic Davis-Foster <dominic@davis-foster.co.uk>
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
#  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
#  OR OTHER DEALINGS IN THE SOFTWARE.
#

# 3rd party
from domdf_python_tools.words import Plural
from flake8.formatting.base import BaseFormatter  # type: ignore

__author__: str = "Dominic Davis-Foster"
__copyright__: str = "2020 Dominic Davis-Foster"
__license__: str = "MIT License"
__version__: str = "0.1.1"
__email__: str = "dominic@davis-foster.co.uk"

__all__ = ["GitHubFormatter"]

_error = Plural("error", "errors")
_file = Plural("file", "files")


class GitHubFormatter(BaseFormatter):
	"""
	Custom Flake8 formatter for GitHub actions.
	"""

	def write_line(self, line):
		"""
		Override write for convenience.
		"""
		self.write(line, None)

	def start(self):  # noqa: D102
		super().start()
		self.files_reported_count = 0

	def beginning(self, filename):
		"""
		We're starting a new file.
		"""

		self.reported_errors_count = 0

	def finished(self, filename):
		"""
		We've finished processing a file.
		"""

		self.files_reported_count += 1

	def format(self, violation):  # noqa: A003  # pylint: disable=redefined-builtin
		"""
		Format a violation.
		"""

		if self.reported_errors_count == 0:
			self.write_line(violation.filename)

		self.write_line(
				f"::warning "
				f"file={violation.filename},line={violation.line_number},col={violation.column_number}"
				f"::{violation.code}: {violation.text}"
				)

		self.reported_errors_count += 1
