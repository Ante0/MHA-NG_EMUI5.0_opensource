These rules are fairly standard and boring. People will bitch about something
in here, no doubt. Get over it. Much of this was stolen from the Linux Kernel
coding style, because most of it makes good sense. If you disagree, that's OK,
but please stick to the rules anyway ;-)


Language

Please use Python where possible. It's not the ideal language for everything,
but it's pretty good, and consistency goes a long way in making the project
maintainable. (Obviously using C or whatever for writing tests is fine).


Base coding style

When writing python code, unless otherwise stated, stick to the python style
guide (http://www.python.org/dev/peps/pep-0008/).


Indentation & whitespace

Format your code for an 80 character wide screen.

Indentation is now 4 spaces, as opposed to hard tabs (which it used to be).
This is the Python standard.

For hanging indentation, use 8 spaces plus all args should be on the new line.

     # Either of the following hanging indentation is considered acceptable.
YES: return 'class: %s, host: %s, args = %s' % (
             self.__class__.__name__, self.hostname, self.args)

YES: return 'class: %s, host: %s, args = %s' % (
             self.__class__.__name__,
             self.hostname,
             self.args)

     # Do not use 4 spaces for hanging indentation
NO:  return 'class: %s, host: %s, args = %s' % (
         self.__class__.__name__, self.hostname, self.args)

     # Do put all args on new line
NO:  return 'class: %s, host: %s, args = %s' % (self.__class__.__name__,
             self.hostname, self.args)

Don't leave trailing whitespace, or put whitespace on blank lines.

Leave TWO blank lines between functions - this is Python, there are no clear
function end markers, and we need help.


Variable names and UpPeR cAsE

Use descriptive variable names where possible - it helps to make the code
self documenting.

Don't use CamelCaps style in most places - use underscores to separate parts
of your variable_names please. I shall make a bedgrudging exception for class
names I suppose, but I'll still whine about it a lot.


Importing modules

The order of imports should be as follows:

Standard python modules
Non-standard python modules
Autotest modules

Within one of these three sections, all module imports using the from
keyword should appear after regular imports.
Each module should be imported on its own line.
Wildcard imports (from x import *) should be avoided if possible.
Classes should not be imported from modules, but modules may be imported
 from packages, i.e.:
from common_lib import error
and not
from common_lib.error import AutoservError

For example:
import os
import pickle
import random
import re
import select
import shutil
import signal
import subprocess

import common   # Magic autotest_lib module and sys.path setup code.
import MySQLdb  # After common so that we check our site-packages first.

from common_lib import error


Testing None

Use "is None" rather than "== None" and "is not None" rather than "!= None".
This way you'll never run into a case where someone's __eq__ or __ne__
method do the wrong thing


Comments

Generally, you want your comments to tell WHAT your code does, not HOW.
We can figure out how from the code itself (or if not, your code needs fixing).

Try to describle the intent of a function and what it does in a triple-quoted
(multiline) string just after the def line. We've tried to do that in most
places, though undoubtedly we're not perfect. A high level overview is
incredibly helpful in understanding code.


Hardcoded String Formatting

Strings should use only single quotes for hardcoded strings in the code. Double
quotes are acceptable when single quote is used as part of the string.
Multiline string should not use '\' but wrap the string using parenthesises.

REALLY_LONG_STRING = ('This is supposed to be a really long string that is '
                      'over 80 characters and does not use a slash to '
                      'continue.')

Docstrings

Docstrings are important to keep our code self documenting. While it's not
necessary to overdo documentation, we ask you to be sensible and document any
nontrivial function. When creating docstrings, please add a newline at the
beginning of your triple quoted string and another newline at the end of it. If
the docstring has multiple lines, please include a short summary line followed
by a blank line before continuing with the rest of the description. Please
capitalize and punctuate accordingly the sentences. If the description has
multiple lines, put two levels of indentation before proceeding with text. An
example docstring:

def foo(param1, param2):
    """
    Summary line.

    Long description of method foo.

    @param param1: A thing called param1 that is used for a bunch of stuff
            that has methods bar() and baz() which raise SpamError if
            something goes awry.

    @returns a list of integers describing changes in a source tree

    @raises exception that could be raised if a certain condition occurs.

    """

The tags that you can put inside your docstring are tags recognized by systems
like doxygen. Not all places need all tags defined, so choose them wisely while
writing code. Generally (if applicable) always list parameters, return value
(if there is one), and exceptions that can be raised to each docstring.

@author - Code author
@param - Parameter description
@raise - If the function can throw an exception, this tag documents the
possible exception types.
@raises - same as @raise.
@return - Return value description
@returns - Same as @return
@see - Reference to what you have done
@warning - Call attention to potential problems with the code
@var -  Documentation for a variable or enum value (either global or as a
member of a class)
@version - Version string

When in doubt refer to: http://doxygen.nl/commands.html

Simple code

Keep it simple; this is not the right place to show how smart you are. We
have plenty of system failures to deal with without having to spend ages
figuring out your code, thanks ;-) Readbility, readability, readability.
I really don't care if other things are more compact.

"Debugging is twice as hard as writing the code in the first place. Therefore,
if you write the code as cleverly as possible, you are, by definition, not
smart enough to debug it."  Brian Kernighan


Function length

Please keep functions short, under 30 lines or so if possible. Even though
you are amazingly clever, and can cope with it, the rest of us are all stupid,
so be nice and help us out. To quote the Linux Kernel coding style:

Functions should be short and sweet, and do just one thing.  They should
fit on one or two screenfuls of text (the ISO/ANSI screen size is 80x24,
as we all know), and do one thing and do that well.


Exceptions

When raising exceptions, the preferred syntax for it is:

raise FooException('Exception Message')

Please don't raise string exceptions, as they're deprecated and will be removed
from future versions of python. If you're in doubt about what type of exception
you will raise, please look at http://docs.python.org/lib/module-exceptions.html
and client/common_lib/error.py, the former is a list of python built in
exceptions and the later is a list of autotest/autoserv internal exceptions. Of
course, if you really need to, you can extend the exception definitions on
client/common_lib/error.py.


Submitting patches

Generate universal diffs. Email them to autotest@test.kernel.org.
Most mailers now break lines and/or changes tabs to spaces. If you know how
to avoid that - great, put your patches inline. If you're not sure, just
attatch them, I don't care much. Please base them off the current version.

Don't worry about submitting patches to a public list - everybody makes
mistakes, especially me ... so get over it and don't worry about it.
(though do give your changes a test first ;-))
