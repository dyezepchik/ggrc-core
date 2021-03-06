/*!
 Copyright (C) 2017 Google Inc.
 Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>
 */

(function (GGRC) {
  'use strict';
  /**
   * Util methods for work with Current Page.
   */
  GGRC.Utils.CurrentPage = (function () {
    var queryAPI = GGRC.Utils.QueryAPI;
    var relatedToCurrentInstance = new can.Map({});

    var widgetsCounts = new can.Map({});

    function initMappedInstances(dependentModels, current) {
      var models = can.makeArray(dependentModels);
      var reqParams = [];

      models.forEach(function (model) {
        reqParams.push(queryAPI.buildParam(
          model,
          {},
          {
            type: current.type,
            id: current.id,
            operation: 'relevant'
          },
          ['id']));
      });

      return queryAPI.makeRequest({data: reqParams}).then(function (response) {
        models.forEach(function (model, idx) {
          var values = can.makeArray(response[idx][model].values);
          var map = values.reduce(function (mapped, obj) {
            mapped[obj.id] = true;
            return mapped;
          }, {});
          relatedToCurrentInstance.attr(model, map);
        });
        return relatedToCurrentInstance;
      });
    }

    /**
     * Counts for related objects.
     *
     * @return {can.Map} Promise which return total count of objects.
     */
    function getCounts() {
      return widgetsCounts;
    }

    function initCounts(widgets, relevant) {
      var params = can.makeArray(widgets)
        .map(function (widget) {
          var param;
          if (GGRC.Utils.Snapshots.isSnapshotRelated(relevant.type, widget)) {
            param = queryAPI.buildParam('Snapshot', {},
              queryAPI.makeExpression(widget, relevant.type, relevant.id), null,
              GGRC.query_parser.parse('child_type = ' + widget));
          } else if (typeof widget === 'string') {
            param = queryAPI.buildParam(widget, {},
              queryAPI.makeExpression(widget, relevant.type, relevant.id));
          } else {
            param = queryAPI.buildParam(widget.name, {},
              queryAPI.makeExpression(widget.name, relevant.type, relevant.id),
              null, widget.additionalFilter);
          }
          param.type = 'count';
          return param;
        });

      return queryAPI.makeRequest({
        data: params
      }).then(function (data) {
        data.forEach(function (info, i) {
          var widget = widgets[i];
          var name = typeof widget === 'string' ? widget : widget.name;
          var countsName = typeof widget === 'string' ?
            widget : (widget.countsName || widget.name);
          if (GGRC.Utils.Snapshots.isSnapshotRelated(relevant.type, name)) {
            name = 'Snapshot';
          }
          widgetsCounts.attr(countsName, info[name].total);
        });
      });
    }

    return {
      related: relatedToCurrentInstance,
      initMappedInstances: initMappedInstances,
      getCounts: getCounts,
      initCounts: initCounts
    };
  })();
})(window.GGRC);
