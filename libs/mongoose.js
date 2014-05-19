// Contains substantial additions by SLT

var mongoose = require('mongoose');
var log = require('./log')(module);
var config = require('./config');
var crypto = require('crypto');

mongoose.connect(config.get('mongoose:uri'));
var db = mongoose.connection;

db.on('error', function (err) {
    log.error('connection error:', err.message);
});
db.once('open', function callback() {
    log.info("Connected to DB!");
});

var Schema = mongoose.Schema;

// Article

var Images = new Schema({
    kind: {
        type: String,
        enum: ['thumbnail', 'detail'],
        required: true
    },
    url: { type: String, required: true }
});

var Article = new Schema({
    title: { type: String, required: true },
    author: { type: String, required: true },
    description: { type: String, required: true },
    images: [Images],
    modified: { type: Date, default: Date.now }
});

Article.path('title').validate(function (v) {
    return v.length > 5 && v.length < 70;
});

var ArticleModel = mongoose.model('Article', Article);

// User

var User = new Schema({
    username: {
        type: String,
        unique: true,
        required: true
    },
    hashedPassword: {
        type: String,
        required: true
    },
    salt: {
        type: String,
        required: true
    },
    created: {
        type: Date,
        default: Date.now
    }
});

User.methods.encryptPassword = function (password) {
    return crypto.createHmac('sha1', this.salt).update(password).digest('hex');
    //more secure - return crypto.pbkdf2Sync(password, this.salt, 10000, 512);
};

User.virtual('userId')
    .get(function () {
        return this.id;
    });

User.virtual('password')
    .set(function (password) {
        this._plainPassword = password;
        this.salt = crypto.randomBytes(32).toString('base64');
        //more secure - this.salt = crypto.randomBytes(128).toString('base64');
        this.hashedPassword = this.encryptPassword(password);
    })
    .get(function () {
        return this._plainPassword;
    });


User.methods.checkPassword = function (password) {
    return this.encryptPassword(password) === this.hashedPassword;
};

var UserModel = mongoose.model('User', User);

// Client

var Client = new Schema({
    name: {
        type: String,
        unique: true,
        required: true
    },
    clientId: {
        type: String,
        unique: true,
        required: true
    },
    clientSecret: {
        type: String,
        required: true
    }
});

var ClientModel = mongoose.model('Client', Client);

// AccessToken

var AccessToken = new Schema({
    userId: {
        type: String,
        required: true
    },
    clientId: {
        type: String,
        required: true
    },
    token: {
        type: String,
        unique: true,
        required: true
    },
    created: {
        type: Date,
        default: Date.now
    }
});

var AccessTokenModel = mongoose.model('AccessToken', AccessToken);

// RefreshToken

var RefreshToken = new Schema({
    userId: {
        type: String,
        required: true
    },
    clientId: {
        type: String,
        required: true
    },
    token: {
        type: String,
        unique: true,
        required: true
    },
    created: {
        type: Date,
        default: Date.now
    }
});

var RefreshTokenModel = mongoose.model('RefreshToken', RefreshToken);

/*
 Beginning of Soluz-Specific Data Model Items  (by SLT) ...

 */
Objectid = mongoose.Schema.ObjectId;

var Group;
Group = new Schema({
    list_of_users: [User],
    name: String,
    leader: String,
    properties: {
        type: Objectid
    }
});
var GroupModel = mongoose.model('Group', Group);

var Param_Spec;
Param_Spec = new Schema({
    name: String,
    type: String,
    validator: String,
    param_generator: String // optional code
});
var ParamSpecModel = mongoose.model('Param_Spec', Param_Spec);

var Operator;
Operator = new Schema({
    name: String,
    param_list: [Param_Spec],
    precondition: String,
    state_trans_function: String
});
var OperatorModel = mongoose.model('Operator', Operator);

var OpWithParams;
OpWithParams = new Schema({
    op: String, //Operator,
    args: [Object] // values of any needed parameters
});
var OpWithParamsModel = mongoose.model('OpWithParams', OpWithParams);

var State;
State = new Schema({
    value: Objectid,
    ancestor: Objectid, // State
    op_sequence: [OpWithParams]
});
var StateModel = mongoose.model('State', State);

var Problem;
Problem = new Schema({
    name: String,
    initial_state: [State], // Just one state, but Mongoose objects so we have an array.
    operators: [Operator],
    state_vis_code: String,
    prob_space_vis_code: String,
    parameter_generators: [String],
    evaluation_functions: [String]
});
var ProblemModel = mongoose.model('Problem', Problem);

var Role;
Role = new Schema({
    name: String,
    problem: [Problem], // Just 1 problem, but Mongoose objects so we have an array.
    operators: [Operator]
});
var RoleModel = mongoose.model('Role', Role);

var Role_Assignment;
Role_Assignment = new Schema({
    role: [Role], // Really only 1 role, but Mongoose likes arrays
    user: [User]  // Really one 1 user, etc.
});
var RoleAssignmentModel = mongoose.model('Role_Assignment', Role_Assignment);

var Annotation;
Annotation = new Schema({
    author: Objectid, // User
    type: String,
    body: String
})
var Session;
Session = new Schema({
    group: Objectid, //Group,
    common_data: Objectid,
    problem: Objectid, //Problem,
    session_tree: [State],
    annotations: [Annotation],
    role_assignments: [Role_Assignment]
});
var SessionModel = mongoose.model('Session', Session);

var Agent;
Agent = new Schema({
    generality_type: {
        type: String,
        enum: ['template', 'specific']
    },
    task_type: {
        type: String,
        enum: ['eval', 'create', 'both']
    },
    eval_fn: String, //Evaluation_Function,
    parameter_generators: [String],
    operators_allowed: [Operator],
    verbosity: {
        type: String,
        enum: ['silent', 'terse', 'verbose']
    },
    reporting_interval: Number,
    pause: Boolean
});
var AgentModel = mongoose.model('Agent', Agent);

var Node;
Node = new Schema({
    state: Objectid, //State,
    parent: Objectid, //State,
    vis: Objectid, //Images,
    annotations: [Annotation]
});
var NodeModel = mongoose.model('Node', Node);

var Node_ViewProp_Pair;
Node_ViewProp_Pair = new Schema({
    node: Objectid, //Node,
    view_prop: String
});
var NodeViewPropPairModel = mongoose.model('Node_ViewProp_Pair', Node_ViewProp_Pair);

var View;
View = new Schema({
    name: String,
    session: Objectid, //Session,
    overlay: [Node_ViewProp_Pair]
});
var ViewModel = mongoose.model('View', View);

module.exports.mongoose = mongoose;
module.exports.ArticleModel = ArticleModel;
module.exports.UserModel = UserModel;
module.exports.ClientModel = ClientModel;
module.exports.AccessTokenModel = AccessTokenModel;
module.exports.RefreshTokenModel = RefreshTokenModel;

module.exports.GroupModel = GroupModel;
module.exports.ParamSpecModel = ParamSpecModel;
module.exports.OperatorModel = OperatorModel;
module.exports.StateModel = StateModel;
module.exports.ProblemModel = ProblemModel;
module.exports.RoleModel = RoleModel;
module.exports.RoleAssignmentModel = RoleAssignmentModel;
module.exports.SessionModel = SessionModel;
module.exports.AgentModel = AgentModel;
module.exports.NodeModel = NodeModel;
module.exports.NodeViewPropPairModel = NodeViewPropPairModel;
module.exports.ViewModel = ViewModel;
