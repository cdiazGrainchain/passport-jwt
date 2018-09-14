'use strict';
var g = require('./globalize');
var DataSource = require('loopback-datasource-juggler').DataSource;
var Registry = require('./registry');
var assert = require('assert');
var fs = require('fs');
var extend = require('util')._extend;
var RemoteObjects = require('strong-remoting');
var classify = require('underscore.string/classify');
var camelize = require('underscore.string/camelize');
var path = require('path');
var util = require('util');
var routes = require('./routes');


function App() {
  // this is a dummy placeholder for jsdox
}

/*!
 * Export the app prototype.
 */

var app = module.exports = {};

app.remotes = function() {
  if (this._remotes) {
    return this._remotes;
  } else {
    var options = {};

    if (this.get) {
      options = this.get('remoting');
    }

    return (this._remotes = RemoteObjects.create(options));
  }
};

/*!
 * Remove a route by reference.
 */

app.disuse = function(route) {
  if (this.stack) {
    for (var i = 0; i < this.stack.length; i++) {
      if (this.stack[i].route === route) {
        this.stack.splice(i, 1);
      }
    }
  }
};

app.model = function(Model, config) {
  var isPublic = true;
  var registry = this.registry;

  if (typeof Model === 'string') {
var msg = 'app.model(modelName, settings) is no longer supported. ' +
      'Use app.registry.createModel(modelName, definition) and ' +
      'app.model(ModelCtor, config) instead.';
    throw new Error(msg);
  }

  if (arguments.length > 1) {
    config = config || {};
    configureModel(Model, config, this);
    isPublic = config.public !== false;
  } else {
    assert(Model.prototype instanceof Model.registry.getModel('Model'),
      Model.modelName + ' must be a descendant of loopback.Model');
  }

  var modelName = Model.modelName;
  this.models[modelName] =
    this.models[classify(modelName)] =
      this.models[camelize(modelName)] = Model;

  this.models().push(Model);

  if (isPublic && Model.sharedClass) {
    this.remotes().defineObjectType(Model.modelName, function(data) {
      return new Model(data);
    });
    this.remotes().addClass(Model.sharedClass);
    if (Model.settings.trackChanges && Model.Change) {
      this.remotes().addClass(Model.Change.sharedClass);
    }
    clearHandlerCache(this);
    this.emit('modelRemoted', Model.sharedClass);
  }

  var self = this;
  Model.on('remoteMethodDisabled', function(model, methodName) {
    self.emit('remoteMethodDisabled', model, methodName);
  });

  Model.shared = isPublic;
  Model.app = this;
  Model.emit('attached', this);
  return Model;
};


app.models = function() {
  return this._models || (this._models = []);
};


app.dataSource = function(name, config) {
  try {
    var ds = dataSourcesFromConfig(name, config, this.connectors, this.registry);
    this.dataSources[name] =
    this.dataSources[classify(name)] =
    this.dataSources[camelize(name)] = ds;
    ds.app = this;
    return ds;
  } catch (err) {
    if (err.message) {
      err.message = g.f('Cannot create data source %s: %s',
        JSON.stringify(name), err.message);
    }
    throw err;

   }
};


app.connector = function(name, connector) {
  this.connectors[name] =
  this.connectors[classify(name)] =
  this.connectors[camelize(name)] = connector;
};


app.remoteObjects = function() {
  var result = {};

  this.remotes().classes().forEach(function(sharedClass) {
    result[sharedClass.name] = sharedClass.ctor;
  });

  return result;
};


app.handler = function(type, options) {
  var handlers = this._handlers || (this._handlers = {});
  if (handlers[type]) {
    return handlers[type];
  }

  var remotes = this.remotes();
  var handler = this._handlers[type] = remotes.handler(type, options);

  remotes.classes().forEach(function(sharedClass) {
    sharedClass.ctor.emit('mounted', app, sharedClass, remotes);
  });

  return handler;
};

app.dataSources = app.datasources = {};

app.enableAuth = function(options) {
  var AUTH_MODELS = ['User', 'AccessToken', 'ACL', 'Role', 'RoleMapping'];

  var remotes = this.remotes();
  var app = this;

  if (options && options.dataSource) {
    var appModels = app.registry.modelBuilder.models;
    AUTH_MODELS.forEach(function(m) {
      var Model = app.registry.findModel(m);
      if (!Model) {
        throw new Error(
          g.f('Authentication requires model %s to be defined.', m));
      }

      if (Model.dataSource || Model.app) return;
      for (var name in appModels) {
        var candidate = appModels[name];
        var isSubclass = candidate.prototype instanceof Model;
        var isAttached = !!candidate.dataSource || !!candidate.app;
        if (isSubclass && isAttached) return;
      }

      app.model(Model, {
        dataSource: options.dataSource,
        public: m === 'User',
      });
    });
  }

  remotes.authorization = function(ctx, next) {
    var method = ctx.method;
    var req = ctx.req;
    var Model = method.ctor;
    var modelInstance = ctx.instance;

    var modelId = modelInstance && modelInstance.id ||
      // replacement for deprecated req.param()
      (req.params && req.params.id !== undefined ? req.params.id :
       req.body && req.body.id !== undefined ? req.body.id :
       req.query && req.query.id !== undefined ? req.query.id :
       undefined);

    var modelName = Model.modelName;

    var modelSettings = Model.settings || {};

    var errStatusCode = modelSettings.aclErrorStatus || app.get('aclErrorStatus') || 401;
     if (!req.accessToken) {
      errStatusCode = 401;
    }

    if (Model.checkAccess) {
      Model.checkAccess(
        req.accessToken,
        modelId,
        method,
        ctx,
        function(err, allowed) {
          if (err) {
            console.log(err);
            next(err);
          } else if (allowed) {
            next();
          } else {
            var access=0;
            for(let i in routes){
              if(routes[i].url==modelName){
                access=1;
              }
            }
            if(access==1){
             next();
            }else{

             var messages = {
              403: {
                message: g.f('Access Denied'),
                 code: 'ACCESS_DENIED',
              },
              404: {
                message: (g.f('could not find %s with id %s', modelName, modelId)),
                code: 'MODEL_NOT_FOUND',
              },
              401: {
                message: g.f('Authorization Required'),
                code: 'AUTHORIZATION_REQUIRED',
              },
            };

            var e = new Error(messages[errStatusCode].message || messages[403].message);
            e.statusCode = errStatusCode;
            e.code = messages[errStatusCode].code || messages[403].code;
            next(e);
           }
          }
        }
      );
    } else {
      next();
    }
  };

  this.isAuthEnabled = true;
};

app.boot = function(options) {
  throw new Error(
  	g.f('{{`app.boot`}} was removed, use the new module {{loopback-boot}} instead'));
};

function dataSourcesFromConfig(name, config, connectorRegistry, registry) {
  var connectorPath;

  assert(typeof config === 'object',
    'can not create data source without config object');

  if (typeof config.connector === 'string') {
    name = config.connector;
    if (connectorRegistry[name]) {
      config.connector = connectorRegistry[name];
    } else {
      connectorPath = path.join(__dirname, 'connectors', name + '.js');

      if (fs.existsSync(connectorPath)) {
        config.connector = require(connectorPath);
      }
    }
    if (config.connector && typeof config.connector === 'object' && !config.connector.name)
      config.connector.name = name;
  }

  return registry.createDataSource(config);
}

function configureModel(ModelCtor, config, app) {
  assert(ModelCtor.prototype instanceof ModelCtor.registry.getModel('Model'),
    ModelCtor.modelName + ' must be a descendant of loopback.Model');

  var dataSource = config.dataSource;

  if (dataSource) {
    if (typeof dataSource === 'string') {
      dataSource = app.dataSources[dataSource];
    }

    assert(
      dataSource instanceof DataSource,
      ModelCtor.modelName + ' is referencing a dataSource that does not exist: "' +
      config.dataSource + '"'
    );
  }

  config = extend({}, config);
  config.dataSource = dataSource;

  setSharedMethodSharedProperties(ModelCtor, app, config);

  app.registry.configureModel(ModelCtor, config);
}

function setSharedMethodSharedProperties(model, app, modelConfigs) {
  var settings = {};

  // apply config.json settings
  var config = app.get('remoting');
  var configHasSharedMethodsSettings = config &&
      config.sharedMethods &&
      typeof config.sharedMethods === 'object';
  if (configHasSharedMethodsSettings)
    util._extend(settings, config.sharedMethods);

  // apply model-config.json settings
  var modelConfig = modelConfigs.options;
  var modelConfigHasSharedMethodsSettings = modelConfig &&
      modelConfig.remoting &&
      modelConfig.remoting.sharedMethods &&
      typeof modelConfig.remoting.sharedMethods === 'object';
  if (modelConfigHasSharedMethodsSettings)
    util._extend(settings, modelConfig.remoting.sharedMethods);

  // validate setting values
  Object.keys(settings).forEach(function(setting) {
    var settingValue = settings[setting];
    var settingValueType = typeof settingValue;
    if (settingValueType !== 'boolean')
      throw new TypeError(g.f('Expected boolean, got %s', settingValueType));
  });

  // set sharedMethod.shared using the merged settings
  var sharedMethods = model.sharedClass.methods({includeDisabled: true});
  sharedMethods.forEach(function(sharedMethod) {
    // use the specific setting if it exists
    var hasSpecificSetting = settings.hasOwnProperty(sharedMethod.name);
    if (hasSpecificSetting) {
      sharedMethod.shared = settings[sharedMethod.name];
    } else { // otherwise, use the default setting if it exists
      var hasDefaultSetting = settings.hasOwnProperty('*');
      if (hasDefaultSetting)
        sharedMethod.shared = settings['*'];
    }
  });
}

function clearHandlerCache(app) {
  app._handlers = undefined;
}

app.listen = function(cb) {
  var self = this;

  var server = require('http').createServer(this);

  server.on('listening', function() {
    self.set('port', this.address().port);

    var listeningOnAll = false;
    var host = self.get('host');
    if (!host) {
      listeningOnAll = true;
      host = this.address().address;
      self.set('host', host);
    } else if (host === '0.0.0.0' || host === '::') {
      listeningOnAll = true;
    }

    if (!self.get('url')) {
      if (process.platform === 'win32' && listeningOnAll) {
        // Windows browsers don't support `0.0.0.0` host in the URL
        // We are replacing it with localhost to build a URL
        // that can be copied and pasted into the browser.
        host = 'localhost';
      }
      var url = 'http://' + host + ':' + self.get('port') + '/';
      self.set('url', url);
    }
  });

  var useAppConfig =
    arguments.length === 0 ||
      (arguments.length == 1 && typeof arguments[0] == 'function');

  if (useAppConfig) {
    var port = this.get('port');
    // NOTE(bajtos) port:undefined no longer works on node@6,
    // we must pass port:0 explicitly
    if (port === undefined) port = 0;
    server.listen(port, this.get('host'), cb);
  } else {
    server.listen.apply(server, arguments);
  }

  return server;
};
