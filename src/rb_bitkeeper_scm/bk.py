# This version is just a skeleton to show we can register with ReviewBoard

from __future__ import unicode_literals

import base64
import inspect
import logging
import os
import subprocess
import sys
import warnings

from django.utils import six
from django.utils.six.moves.urllib.error import HTTPError
from django.utils.six.moves.urllib.parse import urlparse
from django.utils.six.moves.urllib.request import (Request as URLRequest,
                                                   urlopen)
from django.utils.translation import ugettext_lazy as _

import reviewboard.diffviewer.parser as diffparser
from reviewboard.scmtools.core import SCMTool, SCMClient, HEAD
from reviewboard.scmtools.errors import (AuthenticationError,
                                         FileNotFoundError,
                                         SCMError)
from reviewboard.ssh import utils as sshutils
from reviewboard.ssh.errors import SSHAuthenticationError


__all__ = ('BkTool', 'BkClient')


class BkTool(SCMTool):
    """A backend for talking to a BitKeeper repository.
    This is responsible for handling all the communication with a repository
    and working with data provided by a repository. This includes validating
    repository configuration, fetching file contents, returning log information
    for browsing commits, constructing a diff parser for the repository's
    supported diff format(s), and more.
    Attributes:
        repository (reviewboard.scmtools.models.Repository):
            The repository owning an instance of this SCMTool.
    """

    #: The human-readable name of the SCMTool.
    #:
    #: Users will see this when they go to select a repository type. Some
    #: examples would be "Subversion" or "Perforce".
    name = "BitKeeper"

    #: Whether server-side pending changesets are supported.
    #:
    #: These are used by some types of repositories to track what changes
    #: are currently open by what developer, what files they touch, and what
    #: the commit message is. Basically, they work like server-side drafts for
    #: commits.
    #:
    #: If ``True``, Review Board will allow updating the review request's
    #: information from the pending changeset, and will indicate in the UI
    #: if it's pending or submitted.
    supports_pending_changesets = True

    #: Whether existing commits can be browsed and posted for review.
    #:
    #: If ``True``, the New Review Request page and API will allow for
    #: browsing and posting existing commits and their diffs for review.
    supports_post_commit = False

    #: Whether custom URL masks can be defined to fetching file contents.
    #:
    #: Some systems (such as Git) have no way of accessing an individual file
    #: in a repository over a network without having a complete up-to-date
    #: checkout accessible to the Review Board server. For those, Review Board
    #: can offer a field for specifying a URL mask (a URL with special strings
    #: acting as a template) that will be used when pulling down the contents
    #: of a file referenced in a diff.
    #:
    #: If ``True``, this field will be shown in the repository configuration.
    #: It's up to the SCMTool to handle and parse the value.
    supports_raw_file_urls = False

    #: Whether ticket-based authentication is supported.
    #:
    #: Ticket-based authentication is an authentication method where the
    #: SCMTool requests an authentication ticket from the repository, in order
    #: to access repository content. For these setups, the SCMTool must handle
    #: determining when it needs a new ticket and requesting it, generally
    #: based on the provided username and password.
    #:
    #: If ``True``, an option will be shown for enabling this when configuring
    #: the repository. It's up to the SCMTool to make use of it.
    supports_ticket_auth = False

    #: Overridden help text for the configuration form fields.
    #:
    #: This allows the form fields to have custom help text for the SCMTool,
    #: providing better guidance for configuration.
    field_help_text = {
        'path': _('The path to the repository. This will generally be the URL '
                  'you would use to check out the repository.'),
    }

    #: A dictionary containing lists of dependencies needed for this SCMTool.
    #:
    #: This should be overridden by subclasses that require certain external
    #: modules or binaries. It has two keys: ``executables`` and ``modules``.
    #: Each map to a list of names.
    #:
    #: The list of Python modules go in ``modules``, and must be valid,
    #: importable modules. If a module is not available, the SCMTool will
    #: be disabled.
    #:
    #: The list of executables shouldn't contain a file extensions (e.g.,
    #: ``.exe``), as Review Board will automatically attempt to use the
    #: right extension for the platform.
    dependencies = {
        'executables': ['bk'],
        'modules': [],
    }

    def __init__(self, repository):
        """Initialize the SCMTool.
        This will be initialized on demand, when first needed by a client
        working with a repository. It will generally be bound to the lifetime
        of the repository instance.
        Args:
            repository (reviewboard.scmtools.models.Repository):
                The repository owning this SCMTool.
        """
        super(BkTool, self).__init__(repository)

    def get_file(self, path, revision=HEAD, base_commit_id=None, **kwargs):
        """Return the contents of a file from a repository.
        This attempts to return the raw binary contents of a file from the
        repository, given a file path and revision.
        It may also take a base commit ID, which is the ID (SHA or revision
        number) of a commit changing or introducing the file. This may differ
        from the revision for some types of repositories, where different IDs
        are used for a file content revision and a commit revision.
        Subclasses must implement this.
        Args:
            path (unicode):
                The path to the file in the repository.
            revision (Revision, optional):
                The revision to fetch. Subclasses should default this to
                :py:data:`HEAD`.
            base_commit_id (unicode, optional):
                The ID of the commit that the file was changed in. This may
                not be provided, and is dependent on the type of repository.
            **kwargs (dict):
                Additional keyword arguments. This is not currently used, but
                is available for future expansion.
        Returns:
            bytes:
            The returned file contents.
        Raises:
            reviewboard.scmtools.errors.FileNotFoundError:
                The file could not be found in the repository.
            reviewboard.scmtools.errors.InvalidRevisionFormatError:
                The ``revision`` or ``base_commit_id`` arguments were in an
                invalid format.
        """
        raise NotImplementedError

    def file_exists(self, path, revision=HEAD, base_commit_id=None, **kwargs):
        """Return whether a particular file exists in a repository.
        Like :py:meth:`get_file`, this may take a base commit ID, which is the
        ID (SHA or revision number) of a commit changing or introducing the
        file. This depends on the type of repository, and may not be provided.
        Subclasses should only override this if they have a more efficient
        way of checking for a file's existence than fetching the file contents.
        Args:
            path (unicode):
                The path to the file in the repository.
            revision (Revision, optional):
                The revision to fetch. Subclasses should default this to
                :py:data:`HEAD`.
            base_commit_id (unicode, optional):
                The ID of the commit that the file was changed in. This may
                not be provided, and is dependent on the type of repository.
            **kwargs (dict):
                Additional keyword arguments. This is not currently used, but
                is available for future expansion.
        Returns:
            bool:
            ``True`` if the file exists in the repository. ``False`` if it
            does not (or the parameters supplied were invalid).
        """
        argspec = inspect.getargspec(self.get_file)

        try:
            if argspec.keywords is None:
                warnings.warn('SCMTool.get_file() must take keyword '
                              'arguments, signature for %s is deprecated.'
                              % self.name, DeprecationWarning)
                self.get_file(path, revision)
            else:
                self.get_file(path, revision, base_commit_id=base_commit_id)

            return True
        except FileNotFoundError:
            return False

    def parse_diff_revision(self, file_str, revision_str, moved=False,
                            copied=False, **kwargs):
        """Return a parsed filename and revision as represented in a diff.
        A diff may use strings like ``(working copy)`` as a revision. This
        function will be responsible for converting this to something
        Review Board can understand.
        Args:
            file_str (unicode):
                The filename as represented in the diff.
            revision_str (unicode):
                The revision as represented in the diff.
            moved (bool, optional):
                Whether the file was marked as moved in the diff.
            copied (bool, optional):
                Whether the file was marked as copied in the diff.
            **kwargs (dict):
                Additional keyword arguments. This is not currently used, but
                is available for future expansion.
        Returns:
            tuple:
            A tuple containing two items: The normalized filename string, and
            a :py:class:`Revision`.
        Raises:
            reviewboard.scmtools.errors.InvalidRevisionFormatError:
                The ``revision`` or ``base_commit_id`` arguments were in an
                invalid format.
        """
        raise NotImplementedError

    # TODO: This really should become an attribute, rather than a function.
    def get_diffs_use_absolute_paths(self):
        """Return whether filenames in diffs are stored using absolute paths.
        This is used when uploading and validating diffs to determine if the
        user must supply the base path for a diff. Some types of SCMs
        (such as Subversion) store relative paths in diffs, requiring
        additional information in order to generate an absolute path for
        lookups.
        Subclasses must override this if their diff formats list absolute
        paths.
        Returns:
            bool:
            ``True`` if the diffs store filenames as absolute paths.
            ``False`` if the filenames are stored using relative paths.
        """
        return False

    def get_changeset(self, changesetid, allow_empty=False):
        """Return information on a server-side changeset with the given ID.
        This only needs to be implemented if
        :py:attr:`supports_pending_changesets` is ``True``.
        Args:
            changesetid (unicode):
                The server-side changeset ID.
            allow_empty (bool, optional):
                Whether or not an empty changeset (one containing no modified
                files) can be returned.
                If ``True``, the changeset will be returned with whatever
                data could be provided. If ``False``, a
                :py:exc:`reviewboard.scmtools.errors.EmptyChangeSetError`
                will be raised.
                Defaults to ``False``.
        Returns:
            ChangeSet:
            The resulting changeset containing information on the commit
            and modified files.
        Raises:
            NotImplementedError:
                Changeset retrieval is not available for this type of
                repository.
            reviewboard.scmtools.errors.EmptyChangeSetError:
                The resulting changeset contained no file modifications (and
                ``allow_empty`` was ``False``).
        """
        raise NotImplementedError

    def get_repository_info(self):
        """Return information on the repository.
        The information will vary based on the repository. This data will be
        used in the API, and may be used by clients to better locate or match
        particular repositories.
        It is recommended that it contain a ``uuid`` field containing a unique
        identifier for the repository, if available.
        This is optional, and does not need to be implemented by subclasses.
        Returns:
            dict:
            A dictionary containing information on the repository.
        Raises:
            NotImplementedError:
                Repository information retrieval is not implemented by this
                type of repository. Callers should specifically check for this,
                as it's considered a valid result.
        """
        raise NotImplementedError

    def get_branches(self):
        """Return a list of all branches on the repository.
        This will fetch a list of all known branches for use in the API and
        New Review Request page.
        Subclasses that override this must be sure to always return one (and
        only one) :py:class:`Branch` result with ``default`` set to ``True``.
        Callers should check :py:attr:`supports_post_commit` before calling
        this.
        Returns:
            list of Branch:
            The list of branches in the repository. One (and only one) will
            be marked as the default branch.
        Raises:
            NotImplementedError:
                Branch retrieval is not available for this type of repository.
        """
        raise NotImplementedError

    def get_commits(self, branch=None, start=None):
        """Return a list of commits backward in history from a given point.
        This will fetch a batch of commits from the repository for use in the
        API and New Review Request page.
        The resulting commits will be in order from newest to oldest, and
        should return upwards of a fixed number of commits (usually 30, but
        this depends on the type of repository and its limitations). It may
        also be limited to commits that exist on a given branch (if supported
        by the repository).
        This can be called multiple times in succession using the
        :py:attr:`Commit.parent` of the last entry as the ``start`` parameter
        in order to paginate through the history of commits in the repository.
        Callers should check :py:attr:`supports_post_commit` before calling
        this.
        Args:
            branch (unicode, optional):
                The branch to limit commits to. This may not be supported by
                all repositories.
            start (unicode, optional):
                The commit to start at. If not provided, this will fetch the
                first commit in the repository.
        Returns:
            list of Commit:
            The list of commits, in order from newest to oldest.
        Raises:
            NotImplementedError:
                Commits retrieval is not available for this type of repository.
        """
        raise NotImplementedError

    def get_change(self, revision):
        """Return an individual change/commit with the given revision.
        This will fetch information on the given commit, if found, including
        its commit message and list of modified files.
        Callers should check :py:attr:`supports_post_commit` before calling
        this.
        Args:
            revision (unicode):
                The revision/ID of the commit.
        Returns:
            Commit:
            The resulting commit with the given revision/ID.
        Raises:
            reviewboard.scmtools.errors.SCMError:
                Error retrieving information on this commit.
        """
        raise NotImplementedError

    def get_fields(self):
        """Return fields to show in diff uploading forms.
        .. deprecated:: 2.0
           This is no longer used as of Review Board 2.0.
        """
        # This is kind of a crappy mess in terms of OO design.  Oh well.
        # Return a list of fields which are valid for this tool in the "new
        # review request" page.
        raise NotImplementedError

    def get_parser(self, data):
        """Return a diff parser used to parse diff data.
        The diff parser will be responsible for parsing the contents of the
        diff, and should expect (but validate) that the diff content is
        appropriate for the type of repository.
        Subclasses should override this.
        Args:
            data (bytes):
                The diff data to parse.
        Returns:
            reviewboard.diffviewer.diffparser.DiffParser:
            The diff parser used to parse this data.
        """
        return diffparser.DiffParser(data)

    def normalize_path_for_display(self, filename):
        """Normalize a path from a diff for display to the user.
        This can take a path/filename found in a diff and normalize it,
        stripping away unwanted information, so that it displays in a better
        way in the diff viewer.
        By default, this returns the path as-is.
        Args:
            filename (unicode):
                The filename/path to normalize.
        Returns:
            unicode:
            The resulting filename/path.
        """
        return filename

    def normalize_patch(self, patch, filename, revision):
        """Normalize a diff/patch file before it's applied.
        This can be used to take an uploaded diff file and modify it so that
        it can be properly applied. This may, for instance, uncollapse
        keywords or remove metadata that would confuse :command:`patch`.
        By default, this returns the contents as-is.
        Args:
            patch (bytes):
                The diff/patch file to normalize.
            filename (unicode):
                The name of the file being changed in the diff.
            revision (unicode):
                The revision of the file being changed in the diff.
        Returns:
            bytes:
            The resulting diff/patch file.
        """
        return patch

    @classmethod
    def popen(cls, command, local_site_name=None):
        """Launch an application and return its output.
        This wraps :py:func:`subprocess.Popen` to provide some common
        parameters and to pass environment variables that may be needed by
        :command:`rbssh` (if used). It also ensures the :envvar:`PYTHONPATH`
        environment variable is set correctly, so that Review Board's expected
        modules are used.
        Args:
            command (list of unicode):
                The command to execute.
            local_site_name (unicode, optional):
                The name of the Local Site being used, if any.
        Returns:
            bytes:
            The combined output (stdout and stderr) from the command.
        Raises:
            OSError:
                Error when invoking the command. See the
                :py:func:`subprocess.Popen` documentation for more details.
        """
        env = os.environ.copy()

        if local_site_name:
            env[b'RB_LOCAL_SITE'] = local_site_name.encode('utf-8')

        env[b'PYTHONPATH'] = (':'.join(sys.path)).encode('utf-8')

        return subprocess.Popen(command,
                                env=env,
                                stderr=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                close_fds=(os.name != 'nt'))

    @classmethod
    def check_repository(cls, path, username=None, password=None,
                         local_site_name=None):
        """Check a repository configuration for validity.
        This should check if a repository exists and can be connected to.
        This will also check if the repository requires an HTTPS certificate.
        The result, if the repository configuration is invalid, is returned as
        an exception. The exception may contain extra information, such as a
        human-readable description of the problem. Many types of errors can
        be returned, based on issues with the repository, authentication,
        HTTPS certificate, or SSH keys.
        If the repository configuration is valid and a connection can be
        established, this will simply return.
        Subclasses should override this to provide more specific validation
        logic.
        Args:
            path (unicode):
                The repository path.
            username (unicode, optional):
                The optional username for the repository.
            password (unicode, optional):
                The optional password for the repository.
            local_site_name (unicode, optional):
                The name of the Local Site that owns this repository. This is
                optional.
        Raises:
            reviewboard.scmtools.errors.AuthenticationError:
                The provided username/password or the configured SSH key could
                not be used to authenticate with the repository.
            reviewboard.scmtools.errors.RepositoryNotFoundError:
                A repository could not be found at the given path.
            reviewboard.scmtools.errors.SCMError:
                There was a generic error with the repository or its
                configuration.  Details will be provided in the error message.
            reviewboard.scmtools.errors.UnverifiedCertificateError:
                The SSL certificate on the server could not be verified.
                Information on the certificate will be returned in order to
                allow verification and acceptance using
                :py:meth:`accept_certificate`.
            reviewboard.ssh.errors.BadHostKeyError:
                An SSH path was provided, but the host key for the repository
                did not match the expected key.
            reviewboard.ssh.errors.SSHError:
                An SSH path was provided, but there was an error establishing
                the SSH connection.
            reviewboard.ssh.errors.SSHInvalidPortError:
                An SSH path was provided, but the port specified was not a
                valid number.
            Exception:
                An unexpected exception has ocurred. Callers should check
                for this and handle it.
        """
        if sshutils.is_ssh_uri(path):
            username, hostname = SCMTool.get_auth_from_uri(path, username)
            logging.debug(
                "%s: Attempting ssh connection with host: %s, username: %s"
                % (cls.__name__, hostname, username))

            try:
                sshutils.check_host(hostname, username, password,
                                    local_site_name)
            except SSHAuthenticationError as e:
                # Represent an SSHAuthenticationError as a standard
                # AuthenticationError.
                raise AuthenticationError(e.allowed_types, six.text_type(e),
                                          e.user_key)
            except:
                # Re-raise anything else
                raise

    @classmethod
    def get_auth_from_uri(cls, path, username):
        """Return the username and hostname from the given repository path.
        This is used to separate out a username and a hostname from a path,
        given a string containing ``username@hostname``.
        Subclasses do not need to provide this in most cases. It's used as
        a convenience method for :py:meth:`check_repository`. Subclasses that
        need special parsing logic will generally just replace the behavior
        in that method.
        Args:
            path (unicode):
                The repository path to parse.
            username (unicode):
                The existing username provided in the repository configuration.
        Returns:
            tuple:
            A tuple containing 2 string items: The username, and the hostname.
        """
        url = urlparse(path)

        if '@' in url[1]:
            netloc_username, hostname = url[1].split('@', 1)
        else:
            hostname = url[1]
            netloc_username = None

        if netloc_username:
            return netloc_username, hostname
        else:
            return username, hostname

    @classmethod
    def accept_certificate(cls, path, username=None, password=None,
                           local_site_name=None, certificate=None):
        """Accept the HTTPS certificate for the given repository path.
        This is needed for repositories that support HTTPS-backed
        repositories. It should mark an HTTPS certificate as accepted
        so that the user won't see validation errors in the future.
        The administration UI will call this after a user has seen and verified
        the HTTPS certificate.
        Subclasses must override this if they support HTTPS-backed
        repositories and can offer certificate verification and approval.
        Args:
            path (unicode):
                The repository path.
            username (unicode, optional):
                The username provided for the repository.
            password (unicode, optional):
                The password provided for the repository.
            local_site_name (unicode, optional):
                The name of the Local Site used for the repository, if any.
            certificate (reviewboard.scmtools.certs.Certificate):
                The certificate to accept.
        Returns:
            dict:
            Serialized information on the certificate.
        """
        raise NotImplementedError


class BkClient(SCMClient):
    """Base class for client classes that interface with an SCM.
    Some SCMTools, rather than calling out to a third-party library, provide
    their own client class that interfaces with a command-line tool or
    HTTP-backed repository.
    While not required, this class contains functionality that may be useful to
    such client classes. In particular, it makes it easier to fetch files from
    an HTTP-backed repository, handling authentication and errors.
    Attributes:
        path (unicode):
            The repository path.
        username (unicode, optional):
            The username used for the repository.
        password (unicode, optional):
            The password used for the repository.
    """

    def __init__(self, path, username=None, password=None):
        """Initialize the client.
        Args:
            path (unicode):
                The repository path.
            username (unicode, optional):
                The username used for the repository.
            password (unicode, optional):
                The password used for the repository.
        """
        super(BkClient, self).__init__(path, username, password)

    def get_file_http(self, url, path, revision):
        """Return the contents of a file from an HTTP(S) URL.
        This is a convenience for looking up the contents of files that are
        referenced in diffs through an HTTP(S) request.
        Authentication is performed using the username and password provided
        (if any).
        Args:
            url (unicode):
                The URL to fetch the file contents from.
            path (unicode):
                The path of the file, as referenced in the diff.
            revision (Revision):
                The revision of the file, as referenced in the diff.
        Returns:
            bytes:
            The contents of the file.
        Raises:
            reviewboard.scmtools.errors.FileNotFoundError:
                The file could not be found.
            reviewboard.scmtools.errors.SCMError:
                Unexpected error in fetching the file. This may be an
                unexpected HTTP status code.
        """
        logging.info('Fetching file from %s' % url)

        try:
            request = URLRequest(url)

            if self.username:
                auth_string = base64.b64encode('%s:%s' % (self.username,
                                                          self.password))
                request.add_header('Authorization', 'Basic %s' % auth_string)

            return urlopen(request).read()
        except HTTPError as e:
            if e.code == 404:
                logging.error('404')
                raise FileNotFoundError(path, revision)
            else:
                msg = "HTTP error code %d when fetching file from %s: %s" % \
                      (e.code, url, e)
                logging.error(msg)
                raise SCMError(msg)
        except Exception as e:
            msg = "Unexpected error fetching file from %s: %s" % (url, e)
            logging.error(msg)
            raise SCMError(msg)
