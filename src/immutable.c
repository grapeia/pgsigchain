#include "immutable.h"

#include "commands/trigger.h"
#include "utils/rel.h"

PG_FUNCTION_INFO_V1(pgsigchain_immutable_trigger);

Datum
pgsigchain_immutable_trigger(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	const char  *relname;

	if (!CALLED_AS_TRIGGER(fcinfo))
		ereport(ERROR,
				(errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
				 errmsg("pgsigchain_immutable_trigger: not called as trigger")));

	relname = RelationGetRelationName(trigdata->tg_relation);

	if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
		ereport(ERROR,
				(errcode(ERRCODE_INTEGRITY_CONSTRAINT_VIOLATION),
				 errmsg("pgsigchain: UPDATE not allowed on protected table \"%s\"",
						relname)));

	if (TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
		ereport(ERROR,
				(errcode(ERRCODE_INTEGRITY_CONSTRAINT_VIOLATION),
				 errmsg("pgsigchain: DELETE not allowed on protected table \"%s\"",
						relname)));

	/* Should not reach here, but return tuple just in case */
	PG_RETURN_POINTER(trigdata->tg_trigtuple);
}

PG_FUNCTION_INFO_V1(pgsigchain_truncate_trigger);

Datum
pgsigchain_truncate_trigger(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	const char  *relname;

	if (!CALLED_AS_TRIGGER(fcinfo))
		ereport(ERROR,
				(errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
				 errmsg("pgsigchain_truncate_trigger: not called as trigger")));

	relname = RelationGetRelationName(trigdata->tg_relation);

	ereport(ERROR,
			(errcode(ERRCODE_INTEGRITY_CONSTRAINT_VIOLATION),
			 errmsg("pgsigchain: TRUNCATE not allowed on protected table \"%s\"",
					relname)));

	PG_RETURN_NULL();
}
