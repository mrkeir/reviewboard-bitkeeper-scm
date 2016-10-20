Support for using ReviewBoard with a BitKeeper repository
=========================================================

ReviewBoard does not come with support for BitKeeper repositories
this package is intended to provide that.

If you install it on the machine or in the container that your ReviewBoard is running
and run the django-admin command registerscmtools then bk will be added as a supported
SCM (at least that's the theory - right now you are looking at the start of a PoC).



Credits
-------

- `Distribute`_
- `Buildout`_
- `modern-package-template`_

.. _Buildout: http://www.buildout.org/
.. _Distribute: http://pypi.python.org/pypi/distribute
.. _`modern-package-template`: http://pypi.python.org/pypi/modern-package-template
