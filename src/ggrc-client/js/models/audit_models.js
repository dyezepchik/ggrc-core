/*
 Copyright (C) 2018 Google Inc.
 Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>
 */

import '../components/audit/attach-folder-button'
import RefreshQueue from './refresh_queue';
import Permission from '../permission';

(function (can, CMS) {
  const AUDIT_ISSUE_TRACKER = {
    hotlist_id: '766459',
    component_id: '188208',
    issue_severity: 'S2',
    issue_priority: 'P2',
    issue_type: 'PROCESS',
  };

  can.Model.Cacheable('CMS.Models.Audit', {
    root_object: 'audit',
    root_collection: 'audits',
    category: 'programs',
    findAll: 'GET /api/audits',
    findOne: 'GET /api/audits/{id}',
    update: 'PUT /api/audits/{id}',
    destroy: 'DELETE /api/audits/{id}',
    create: 'POST /api/audits',
    mixins: [
      'accessControlList',
      'unique_title',
      'ca_update',
      'timeboxed',
      'mapping-limit',
      'issueTrackerIntegratable',
    ],
    is_custom_attributable: true,
    is_clonable: true,
    isRoleable: true,
    attributes: {
      context: 'CMS.Models.Context.stub',
      program: 'CMS.Models.Program.stub',
      modified_by: 'CMS.Models.Person.stub',
      report_start_date: 'date',
      report_end_date: 'date',
      object_people: 'CMS.Models.ObjectPerson.stubs',
      people: 'CMS.Models.Person.stubs',
      audit_firm: 'CMS.Models.OrgGroup.stub',
      audit_objects: 'CMS.Models.AuditObject.stubs',
      custom_attribute_values: 'CMS.Models.CustomAttributeValue.stubs',
    },
    defaults: {
      status: 'Planned',
    },
    statuses: ['Planned', 'In Progress', 'Manager Review',
      'Ready for External Review', 'Completed', 'Deprecated'],
    obj_nav_options: {
      show_all_tabs: false,
      force_show_list: ['In Scope Controls', 'Assessment Templates',
        'Issues', 'Assessments'],
    },
    tree_view_options: {
      attr_view: GGRC.mustache_path + '/audits/tree-item-attr.mustache',
      attr_list: [{
        attr_title: 'Title',
        attr_name: 'title',
        order: 1,
      }, {
        attr_title: 'Code',
        attr_name: 'slug',
        order: 3,
      }, {
        attr_title: 'State',
        attr_name: 'status',
        order: 4,
      }, {
        attr_title: 'Last Updated Date',
        attr_name: 'updated_at',
        order: 5,
      }, {
        attr_title: 'Last Updated By',
        attr_name: 'modified_by',
        order: 6,
      }, {
        attr_title: 'Planned Start Date',
        attr_name: 'start_date',
        order: 7,
      }, {
        attr_title: 'Planned End Date',
        attr_name: 'end_date',
        order: 8,
      }, {
        attr_title: 'Last Deprecated Date',
        attr_name: 'last_deprecated_date',
        order: 9,
      }, {
        attr_title: 'Planned Report Period to',
        attr_name: 'report_period',
        attr_sort_field: 'report_end_date',
        order: 10,
      }, {
        attr_title: 'Audit Firm',
        attr_name: 'audit_firm',
        order: 11,
      }, {
        attr_title: 'Archived',
        attr_name: 'archived',
        order: 12,
      }],
      draw_children: true,
    },
    sub_tree_view_options: {
      default_filter: ['Product'],
    },
    init: function () {
      if (this._super) {
        this._super.apply(this, arguments);
      }
      this.validatePresenceOf('program');
      this.validateNonBlank('title');

      this.validate(
        'issue_tracker_component_id',
        function () {
          if (this.attr('issue_tracker.enabled') &&
            !this.attr('issue_tracker.component_id')) {
            return 'cannot be blank';
          }
        }
      );

      this.validate(['_transient.audit_firm', 'audit_firm'],
        function () {
          let auditFirm = this.attr('audit_firm');
          let transientAuditFirm = this.attr('_transient.audit_firm');

          if (!auditFirm && transientAuditFirm) {
            if (_.isObject(transientAuditFirm) &&
              (auditFirm.reify().title !== transientAuditFirm.reify().title) ||
              (transientAuditFirm !== '' && transientAuditFirm !== null &&
              auditFirm !== null &&
              transientAuditFirm !== auditFirm.reify().title)) {
              return 'No valid org group selected for firm';
            }
          }
        }
      );
    },
  }, {
    object_model: function () {
      return CMS.Models[this.attr('object_type')];
    },
    clone: function (options) {
      let model = CMS.Models.Audit;
      return new model({
        operation: 'clone',
        cloneOptions: options.cloneOptions,
        program: this.program,
        title: this.title + new Date(),
      });
    },
    save: function () {
      // Make sure the context is always set to the parent program
      let _super = this._super;
      let args = arguments;
      if (!this.context || !this.context.id) {
        return this.program.reify().refresh().then(function (program) {
          this.attr('context', program.context);
          return _super.apply(this, args);
        }.bind(this));
      }
      return _super.apply(this, args);
    },
    findRoles: function (roleName) {
      const auditRole = GGRC.access_control_roles.find((role) => {
        return role.name === roleName && role.object_type === 'Audit';
      });
      return new can.List(this.access_control_list.filter((item) => {
        return item.ac_role_id === auditRole.id;
      }));
    },
    form_preload() {
      this.initIssueTrackerObject(AUDIT_ISSUE_TRACKER);
    },
  });

  /**
   * A model describing a template for the newly created Assessment objects.
   *
   * This is useful when creating multiple similar Assessment objects. Using an
   * AssessmentTemplate helps avoiding repeatedly defining the same set of
   * Assessment object properties for each new instance.
   */
  can.Model.Cacheable('CMS.Models.AssessmentTemplate', {
    root_object: 'assessment_template',
    root_collection: 'assessment_templates',
    model_singular: 'AssessmentTemplate',
    model_plural: 'AssessmentTemplates',
    title_singular: 'Assessment Template',
    title_plural: 'Assessment Templates',
    table_singular: 'assessment_template',
    table_plural: 'assessment_templates',
    mixins: [
      'mapping-limit',
      'inScopeObjects',
      'inScopeObjectsPreload',
      'refetchHash',
      'issueTrackerIntegratable',
    ],
    findOne: 'GET /api/assessment_templates/{id}',
    findAll: 'GET /api/assessment_templates',
    update: 'PUT /api/assessment_templates/{id}',
    destroy: 'DELETE /api/assessment_templates/{id}',
    create: 'POST /api/assessment_templates',
    is_custom_attributable: false,
    attributes: {
      context: 'CMS.Models.Context.stub',
    },
    defaults: {
      test_plan_procedure: true,
      template_object_type: 'Control',
      default_people: {
        assignees: 'Principal Assignees',
        verifiers: 'Auditors',
      },
      status: 'Draft',
      // the custom lists of assignee / verifier IDs if "other" is selected for
      // the corresponding default_people setting
      assigneesList: {},
      verifiersList: {},
      people_values: [
        {value: 'Admin', title: 'Object Admins'},
        {value: 'Audit Lead', title: 'Audit Captain'},
        {value: 'Auditors', title: 'Auditors'},
        {value: 'Principal Assignees', title: 'Principal Assignees'},
        {value: 'Secondary Assignees', title: 'Secondary Assignees'},
        {value: 'Primary Contacts', title: 'Primary Contacts'},
        {value: 'Secondary Contacts', title: 'Secondary Contacts'},
        {value: 'other', title: 'Others...'},
      ],
      showCaptainAlert: false,
    },
    statuses: ['Draft', 'Deprecated', 'Active'],
    tree_view_options: {
      attr_view: GGRC.mustache_path + '/base_objects/tree-item-attr.mustache',
    },

    /**
     * Initialize the newly created object instance. Validate that its title is
     * non-blank and its default assignees / verifiers lists are set if
     * applicable.
     */
    init: function () {
      this._super.apply(this, arguments);
      this.validateNonBlank('title');
      this.validateNonBlank('default_people.assignees');

      this.validateListNonBlank(
        'assigneesList',
        function () {
          return this.attr('default_people.assignees') === 'other';
        }
      );
      this.validateListNonBlank(
        'verifiersList',
        function () {
          return this.attr('default_people.verifiers') === 'other';
        }
      );
      this.validate(
        'issue_tracker_component_id',
        function () {
          if (this.attr('can_use_issue_tracker') &&
            this.attr('issue_tracker.enabled') &&
            !this.attr('issue_tracker.component_id')) {
            return 'cannot be blank';
          }
        }
      );
    },
  }, {
    /**
     * An event handler when the add/edit form is about to be displayed.
     *
     * It builds a list of all object types used to populate the corresponding
     * dropdown menu on the form.
     * It also deserializes the default people settings so that those form
     * fields are correctly populated.
     *
     * @param {Boolean} isNewObject - true if creating a new instance, false if
     *   editing and existing one
     *
     */
    form_preload: function (isNewObject) {
      const pageInstance = GGRC.page_instance();
      if (!this.custom_attribute_definitions) {
        this.attr('custom_attribute_definitions', new can.List());
      }
      this._unpackPeopleData();

      this._updateDropdownEnabled('assignees');
      this._updateDropdownEnabled('verifiers');

      if (pageInstance && pageInstance.type === 'Audit' && !this.audit) {
        this.audit = {
          id: pageInstance.id,
          title: pageInstance.title,
          type: pageInstance.type,
          context: pageInstance.context,
          issue_tracker: pageInstance.issue_tracker,
        };
      }

      this.initCanUseIssueTracker(this.audit.issue_tracker);
    },

    /**
     * Save the model instance by sending a POST/PUT request to the server
     *
     * @return {can.Deferred} - a deferred object resolved or rejected
     *   depending on the outcome of the undrelying API request
     */
    save: function () {
      this.attr('default_people', this._packPeopleData());

      return this._super.apply(this, arguments);
    },

    after_save: function () {
      if (this.audit) {
        this.audit.reify().refresh();
      }
    },

    /**
     * Event handler when an assignee is picked in an autocomplete form field.
     * It adds the picked assignee's ID to the assignees list.
     *
     * @param {can.Map} context - the Mustache context of the `$el`
     * @param {jQuery.Element} $el - the source of the event `ev`
     * @param {jQuery.Event} ev - the event that was triggered
     */
    assigneeAdded: function (context, $el, ev) {
      let user = ev.selectedItem;
      this.assigneesList.attr(user.id, true);
    },

    /**
     * Event handler when a user clicks to remove an assignee from the
     * assignees list. It removes the corresponding assignee ID from the list.
     *
     * @param {can.Map} context - the Mustache context of the `$el`
     * @param {jQuery.Element} $el - the source of the event `ev`
     * @param {jQuery.Event} ev - the event that was triggered
     */
    assigneeRemoved: function (context, $el, ev) {
      let user = ev.person;
      this.assigneesList.removeAttr(String(user.id));
    },

    /**
     * Event handler when a verifier is picked in an autocomplete form field.
     * It adds the picked verifier's ID to the verifiers list.
     *
     * @param {can.Map} context - the Mustache context of the `$el`
     * @param {jQuery.Element} $el - the source of the event `ev`
     * @param {jQuery.Event} ev - the event that was triggered
     */
    verifierAdded: function (context, $el, ev) {
      let user = ev.selectedItem;
      this.verifiersList.attr(user.id, true);
    },

    /**
     * Event handler when a user clicks to remove a verifier from the verifiers
     * list. It removes the corresponding verifier ID from the list.
     *
     * @param {can.Map} context - the Mustache context of the `$el`
     * @param {jQuery.Element} $el - the source of the event `ev`
     * @param {jQuery.Event} ev - the event that was triggered
     */
    verifierRemoved: function (context, $el, ev) {
      let user = ev.person;
      this.verifiersList.removeAttr(String(user.id));
    },

    /**
     * Event handler when a user changes the default assignees option.
     *
     * @param {can.Map} context - the Mustache context of the `$el`
     * @param {jQuery.Element} $el - the source of the event `ev`
     * @param {jQuery.Event} ev - the event that was triggered
     */
    defaultAssigneesChanged: function (context, $el, ev) {
      let changedList = [
        'Auditors', 'Principal Assignees', 'Secondary Assignees',
        'Primary Contacts', 'Secondary Contacts',
      ];
      this.attr('showCaptainAlert',
        changedList.indexOf(this.default_people.assignees) >= 0);
      this._updateDropdownEnabled('assignees');
    },

    /**
     * Event handler when a user changes the default verifiers option.
     *
     * @param {can.Map} context - the Mustache context of the `$el`
     * @param {jQuery.Element} $el - the source of the event `ev`
     * @param {jQuery.Event} ev - the event that was triggered
     */
    defaultVerifiersChanged: function (context, $el, ev) {
      this._updateDropdownEnabled('verifiers');
    },

    /**
     * Update the autocomplete field's disabled flag based on the current value
     * of the corresponding dropdown.
     *
     * @param {String} name - the value to inspect, must be either "assignees"
     *   or "verifiers"
     */
    _updateDropdownEnabled: function (name) {
      let disable = this.attr('default_people.' + name) !== 'other';
      this.attr(name + 'ListDisable', disable);
    },

    /**
     * Pack the "default people" form data into a JSON string.
     *
     * @return {String} - the JSON-packed default people data
     */
    _packPeopleData: function () {
      let data = {};

      /**
       * Create a sorted (ascending) list of numbers from the given map's keys.
       *
       * @param {can.Map} peopleIds - the map to convert
       * @return {Array} - ordered IDs
       */
      function makeList(peopleIds) {
        let result = Object.keys(peopleIds.attr()).map(Number);
        return result.sort(function (x, y) {
          return x - y;
        });
      }

      data.assignees = this.attr('default_people.assignees');
      data.verifiers = this.attr('default_people.verifiers');

      if (data.assignees === 'other') {
        data.assignees = makeList(this.attr('assigneesList'));
      }

      if (data.verifiers === 'other') {
        data.verifiers = makeList(this.attr('verifiersList'));
      }

      return data;
    },

    /**
     * Inspect the default people settings object, convert any lists of
     * user IDs to comma-separated strings, and use that to populate the
     * corresponding text input fields.
     */
    _unpackPeopleData: function () {
      let instance = this;  // the AssessmentTemplate model instance
      let peopleData = instance.default_people;

      ['assignees', 'verifiers'].forEach(function (name) {
        let idsMap;
        let peopleIds = peopleData[name];

        if (peopleIds instanceof can.List) {
          idsMap = new can.Map();
          peopleIds.forEach(function (id) {
            idsMap.attr(id, true);
          });
          instance.attr(name + 'List', idsMap);
          instance.attr('default_people.' + name, 'other');
        } else {
          instance.attr(name + 'List', {});
        }
      });
    },

    ignore_ca_errors: true,
  });
})(window.can, window.CMS);
