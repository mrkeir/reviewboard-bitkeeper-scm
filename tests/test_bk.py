# coding=utf-8
from __future__ import unicode_literals

import os

import nose
from django.utils import six
from kgb import SpyAgency

from reviewboard.diffviewer.parser import DiffParserError
from reviewboard.scmtools.core import PRE_CREATION
from reviewboard.scmtools.errors import SCMError, FileNotFoundError
from rb_bitkeeper_scm.bk import BkClient
from reviewboard.scmtools.models import Repository, Tool
from reviewboard.scmtools.tests.testcases import SCMTestCase

# NASTY HACK
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'reviewboard.settings'
from django.utils import settings
settings.configure()

class BitKeeperTests(SpyAgency, SCMTestCase):
    """Unit tests for BitKeeper."""

    fixtures = ['test_scmtools']

    def setUp(self):
        super(BitKeeperTests, self).setUp()

        tool = Tool.objects.get(name='BitKeeper')

    def test_dummy(self):
        self.assertTrue(True)


