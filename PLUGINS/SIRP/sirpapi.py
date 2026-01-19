from enum import StrEnum
from typing import List, Dict, Any, Literal, Union

import requests
from pydantic import BaseModel

from Lib.log import logger
from PLUGINS.SIRP.CONFIG import SIRP_NOTICE_WEBHOOK
from PLUGINS.SIRP.nocolyapi import WorksheetRow, OptionSet, Group, Condition, Operator
from PLUGINS.SIRP.sirptype import EnrichmentModel, ArtifactModel, AlertModel, CaseModel, TicketModel


def model_to_fields(model_instance: BaseModel) -> List[Dict[str, Any]]:
    fields = []
    model_data = model_instance.model_dump(mode='json', exclude_unset=True)
    for key, value in model_data.items():
        field_info = model_instance.model_fields.get(key)
        field_item = {
            'id': key,
            'value': value
        }
        if field_info and field_info.json_schema_extra:
            field_item.update(field_info.json_schema_extra)
        fields.append(field_item)
    return fields


class Enrichment(object):
    WORKSHEET_ID = "enrichment"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=True) -> EnrichmentModel:
        result = WorksheetRow.get(Enrichment.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        model = EnrichmentModel(**result)
        return model

    @staticmethod
    def list(model: Group, include_system_fields=True) -> List[EnrichmentModel]:
        filter = model.model_dump()
        result = WorksheetRow.list(Enrichment.WORKSHEET_ID, filter, include_system_fields=include_system_fields)
        model_list = []
        for one in result:
            model_list.append(EnrichmentModel(**one))
        return model_list

    @staticmethod
    def list_by_rowids(rowids: Union[List[str], None], include_system_fields=True) -> Union[List[EnrichmentModel], List[str], None]:
        if rowids is not None and rowids != []:
            filter_model = Group(
                logic="AND",
                children=[
                    Condition(
                        field="rowid",
                        operator=Operator.IN,
                        value=rowids
                    )
                ]
            )
            enrichment_list = Enrichment.list(filter_model, include_system_fields=include_system_fields)
            return enrichment_list
        else:
            return rowids

    @staticmethod
    def update(model: EnrichmentModel) -> str:
        if model.rowid is not None:
            fields = model_to_fields(model)
            rowid = WorksheetRow.update(Enrichment.WORKSHEET_ID, model.rowid, fields)
        else:
            raise Exception("Enrichment rowid is None, cannot update.")
        return rowid

    @staticmethod
    def batch_update(model_list: List[Union[EnrichmentModel, str]]) -> Union[List[str], None]:
        if model_list is not None:
            rowids = []
            for model in model_list:
                if isinstance(model, str):
                    rowids.append(model)  # just link
                    continue
                elif isinstance(model, EnrichmentModel):
                    rowid = Enrichment.update_or_create(model)  # update or create record
                    rowids.append(rowid)
                else:
                    raise Exception("Unsupported enrichment data type")

            return rowids
        else:
            return model_list

    @staticmethod
    def create(model: EnrichmentModel) -> str:
        fields = model_to_fields(model)
        rowid = WorksheetRow.create(Enrichment.WORKSHEET_ID, fields)
        return rowid

    @staticmethod
    def update_or_create(model: EnrichmentModel) -> str:
        fields = model_to_fields(model)
        if model.rowid is None:
            rowid = WorksheetRow.create(Enrichment.WORKSHEET_ID, fields)
        else:
            rowid = WorksheetRow.update(Enrichment.WORKSHEET_ID, model.rowid, fields)
        return rowid


class Ticket(object):
    WORKSHEET_ID = "ticket"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=True) -> TicketModel:
        result = WorksheetRow.get(Ticket.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        model = TicketModel(**result)
        return model

    @staticmethod
    def list(model: Group, include_system_fields=True) -> List[TicketModel]:
        filter = model.model_dump()
        result = WorksheetRow.list(Ticket.WORKSHEET_ID, filter, include_system_fields=include_system_fields)
        model_list = []
        for one in result:
            model_list.append(TicketModel(**one))
        return model_list

    @staticmethod
    def list_by_rowids(rowids: Union[List[str], None], include_system_fields=True) -> Union[List[TicketModel], List[str], None]:
        if rowids is not None and rowids != []:
            filter_model = Group(
                logic="AND",
                children=[
                    Condition(
                        field="rowid",
                        operator=Operator.IN,
                        value=rowids
                    )
                ]
            )
            ticket_list = Ticket.list(filter_model, include_system_fields=include_system_fields)
            return ticket_list
        else:
            return rowids

    @staticmethod
    def update(model: TicketModel) -> str:
        if model.rowid is not None:
            fields = model_to_fields(model)
            rowid = WorksheetRow.update(Ticket.WORKSHEET_ID, model.rowid, fields)
        else:
            raise Exception("Ticket rowid is None, cannot update.")
        return rowid

    @staticmethod
    def batch_update(model_list: List[Union[TicketModel, str]]) -> Union[List[str], None]:
        if model_list is not None:
            rowids = []
            for model in model_list:
                if isinstance(model, str):
                    rowids.append(model)  # just link
                    continue
                elif isinstance(model, TicketModel):
                    rowid = Ticket.update_or_create(model)  # update or create record
                    rowids.append(rowid)
                else:
                    raise Exception("Unsupported ticket data type")

            return rowids
        else:
            return model_list

    @staticmethod
    def create(model: TicketModel) -> str:
        fields = model_to_fields(model)
        rowid = WorksheetRow.create(Ticket.WORKSHEET_ID, fields)
        return rowid

    @staticmethod
    def update_or_create(model: TicketModel) -> str:
        fields = model_to_fields(model)
        if model.rowid is None:
            rowid = WorksheetRow.create(Ticket.WORKSHEET_ID, fields)
        else:
            rowid = WorksheetRow.update(Ticket.WORKSHEET_ID, model.rowid, fields)
        return rowid


class Artifact(object):
    WORKSHEET_ID = "artifact"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=True) -> ArtifactModel:
        result = WorksheetRow.get(Artifact.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        model = ArtifactModel(**result)

        # enrichments
        model.enrichments = Enrichment.list_by_rowids(model.enrichments)

        return model

    @staticmethod
    def list(model: Group, include_system_fields=True) -> List[ArtifactModel]:
        filter = model.model_dump()
        result = WorksheetRow.list(Artifact.WORKSHEET_ID, filter, include_system_fields=include_system_fields)
        artifact_list = []
        for artifact_data in result:
            artifact_model = ArtifactModel(**artifact_data)

            # enrichments
            artifact_model.enrichments = Enrichment.list_by_rowids(artifact_model.enrichments)

            artifact_list.append(artifact_model)
        return artifact_list

    @staticmethod
    def list_by_rowids(rowids: Union[List[str], None], include_system_fields=True) -> Union[List[ArtifactModel], List[str], None]:
        if rowids is not None and rowids != []:
            filter_model = Group(
                logic="AND",
                children=[
                    Condition(
                        field="rowid",
                        operator=Operator.IN,
                        value=rowids
                    )
                ]
            )
            artifact_list = Artifact.list(filter_model, include_system_fields=include_system_fields)
            return artifact_list
        else:
            return rowids

    @staticmethod
    def update_or_create(model: ArtifactModel) -> str:
        # enrichments
        model.enrichments = Enrichment.batch_update(model.enrichments)

        fields = model_to_fields(model)
        if model.rowid is None:
            rowid = WorksheetRow.create(Artifact.WORKSHEET_ID, fields)
        else:
            rowid = WorksheetRow.update(Artifact.WORKSHEET_ID, model.rowid, fields)
        return rowid

    @staticmethod
    def batch_update(model_list: List[Union[ArtifactModel, str]]) -> Union[List[str], None]:
        if model_list is not None:
            rowids = []
            for model in model_list:
                if isinstance(model, str):
                    rowids.append(model)  # just link
                    continue
                elif isinstance(model, ArtifactModel):
                    rowid = Artifact.update_or_create(model)  # update or create record
                    rowids.append(rowid)
                else:
                    raise Exception("Unsupported enrichment data type")

            return rowids
        else:
            return model_list


class Alert(object):
    WORKSHEET_ID = "alert"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=True) -> AlertModel:
        result = WorksheetRow.get(Alert.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        model = AlertModel(**result)

        # artifacts
        model.artifacts = Artifact.list_by_rowids(model.artifacts)

        # enrichments
        model.enrichments = Enrichment.list_by_rowids(model.enrichments)

        return model

    @staticmethod
    def list(model: Group, include_system_fields=True) -> List[AlertModel]:
        filter = model.model_dump()
        result = WorksheetRow.list(Alert.WORKSHEET_ID, filter, include_system_fields=include_system_fields)
        alert_list = []
        for alert_data in result:
            alert_model = AlertModel(**alert_data)

            # artifacts
            alert_model.artifacts = Artifact.list_by_rowids(alert_model.artifacts)

            # enrichments
            alert_model.enrichments = Enrichment.list_by_rowids(alert_model.enrichments)

            alert_list.append(alert_model)
        return alert_list

    @staticmethod
    def list_by_rowids(rowids: Union[List[str], None], include_system_fields=True) -> Union[List[AlertModel], List[str], None]:
        if rowids is not None and rowids != []:
            filter_model = Group(
                logic="AND",
                children=[
                    Condition(
                        field="rowid",
                        operator=Operator.IN,
                        value=rowids
                    )
                ]
            )
            model_list = Alert.list(filter_model, include_system_fields=include_system_fields)
            return model_list
        else:
            return rowids

    @staticmethod
    def update_or_create(model: AlertModel) -> str:

        # artifacts
        model.artifacts = Artifact.batch_update(model.artifacts)

        # enrichments
        model.enrichments = Enrichment.batch_update(model.enrichments)

        fields = model_to_fields(model)
        if model.rowid is None:
            rowid = WorksheetRow.create(Alert.WORKSHEET_ID, fields)
        else:
            rowid = WorksheetRow.update(Alert.WORKSHEET_ID, model.rowid, fields)
        return rowid

    @staticmethod
    def batch_update(model_list: List[Union[AlertModel, str]]) -> Union[List[str], None]:
        if model_list is not None:
            rowids = []
            for model in model_list:
                if isinstance(model, str):
                    rowids.append(model)  # just link
                    continue
                elif isinstance(model, AlertModel):
                    rowid = Alert.update_or_create(model)  # update or create record
                    rowids.append(rowid)
                else:
                    raise Exception("Unsupported enrichment data type")

            return rowids
        else:
            return model_list


class Case(object):
    WORKSHEET_ID = "case"

    def __init__(self):
        pass

    @staticmethod
    def get(rowid, include_system_fields=True) -> CaseModel:
        result = WorksheetRow.get(Case.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)
        model = CaseModel(**result)

        # alerts
        model.alerts = Alert.list_by_rowids(model.alerts)

        # enrichments
        model.enrichments = Enrichment.list_by_rowids(model.enrichments)

        # tickets
        model.tickets = Ticket.list_by_rowids(model.tickets)

        return model

    @staticmethod
    def list(model: Group, include_system_fields=True) -> List[CaseModel]:
        filter = model.model_dump()
        result = WorksheetRow.list(Case.WORKSHEET_ID, filter, include_system_fields=include_system_fields)
        case_list = []
        for case_data in result:
            case_model = CaseModel(**case_data)

            # alerts
            case_model.alerts = Alert.list_by_rowids(case_model.alerts)

            # enrichments
            case_model.enrichments = Enrichment.list_by_rowids(case_model.enrichments)

            # tickets
            case_model.tickets = Ticket.list_by_rowids(case_model.tickets)

            case_list.append(case_model)
        return case_list

    @staticmethod
    def get_raw_data(rowid, include_system_fields=False) -> Dict:
        """Get the raw data of the case and its associated alarms and work orders, and only keep the fields useful for LLM"""
        case = WorksheetRow.get(Case.WORKSHEET_ID, rowid, include_system_fields=include_system_fields)

        useful_case_fields = ["rowid", "title", 'case_status', 'created_date', 'tags', 'severity', 'type', 'description', 'close_reason', 'alert_date',
                              'case_id',
                              'respond_time', 'note', 'acknowledged_date']

        case_clean = {key: case[key] for key in useful_case_fields if key in case}

        # alert id
        alerts = WorksheetRow.relations(Case.WORKSHEET_ID, rowid, "alerts", relation_worksheet_id=Alert.WORKSHEET_ID,
                                        include_system_fields=include_system_fields)
        alerts_clean = []
        for alert in alerts:
            useful_alert_fields = ["rowid", 'severity', 'rule_id', 'rule_name', 'id']
            alert_clean = {key: alert[key] for key in useful_alert_fields if key in alert}

            artifacts = WorksheetRow.relations(Alert.WORKSHEET_ID, alert.get("rowid"), "artifacts", relation_worksheet_id=Artifact.WORKSHEET_ID,
                                               include_system_fields=include_system_fields)
            artifacts_clean = []
            for artifact in artifacts:
                useful_artifact_fields = ["rowid", "type", "value", "enrichment", 'is_whitelisted', 'is_evidence']
                artifact_clean = {key: artifact[key] for key in useful_artifact_fields if key in artifact}
                artifacts_clean.append(artifact_clean)

            alert_clean["artifacts"] = artifacts_clean
            alerts_clean.append(alert_clean)

        case_clean["alerts"] = alerts_clean
        return case_clean

    @staticmethod
    def update_or_create(model: CaseModel) -> str:

        # alerts
        model.alerts = Alert.batch_update(model.alerts)

        # enrichments
        model.enrichments = Enrichment.batch_update(model.enrichments)

        # tickets
        model.tickets = Ticket.batch_update(model.tickets)

        fields = model_to_fields(model)
        if model.rowid is None:
            rowid = WorksheetRow.create(Case.WORKSHEET_ID, fields)
        else:
            rowid = WorksheetRow.update(Case.WORKSHEET_ID, model.rowid, fields)
        return rowid

    @staticmethod
    def get_by_case_id(case_id: str):
        filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "case_id",
                    "operator": "eq",
                    "value": case_id
                },
            ]
        }
        rows = WorksheetRow.list(Case.WORKSHEET_ID, filter)
        if rows:
            if len(rows) > 1:
                logger.warning(f"found multiple rows with case_id {case_id}")
            return Case.get(rows[0]['rowid'])
        else:
            return None


class PlaybookStatus(StrEnum):
    SUCCESS = 'Success'
    FAILED = 'Failed'
    PENDING = 'Pending'
    RUNNING = 'Running'


class Playbook(object):
    WORKSHEET_ID = "playbook"

    def __init__(self):
        pass

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Playbook.WORKSHEET_ID, filter, include_system_fields=False)
        return result

    @staticmethod
    def create(fields: List):
        row_id = WorksheetRow.create(Playbook.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: List):
        row_id = WorksheetRow.update(Playbook.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def update_status_and_remark(row_id, status: PlaybookStatus, remark):
        fields = [
            {"id": "job_status", "value": status},
            {"id": "remark", "value": remark},
        ]
        row_id = WorksheetRow.update(Playbook.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def get_pending_playbooks():
        pending_option_value = OptionSet.get_option_key_by_name_and_value("playbook_status", "Pending")
        artifact_filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "job_status",
                    "operator": "in",
                    "value": [
                        pending_option_value
                    ]
                }
            ]
        }
        result = Playbook.list(artifact_filter)
        return result


class KnowledgeAction(StrEnum):
    STORE = 'Store'
    REMOVE = 'Remove'
    DONE = 'Done'


KnowledgeUsing = Literal[0, 1]


class Knowledge(object):
    WORKSHEET_ID = "knowledge"
    COLLECTION_NAME = "sirp_knowledge"

    def __init__(self):
        pass

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Knowledge.WORKSHEET_ID, filter, include_system_fields=False)
        return result

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Knowledge.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Knowledge.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def update_action_and_using(row_id, action: KnowledgeAction, using: KnowledgeUsing):
        fields = [
            {"id": "action", "value": action},
            {"id": "using", "value": using},
        ]
        row_id = WorksheetRow.update(Knowledge.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def get_undone_actions():
        options = OptionSet.get("knowledge_action")

        action_list = []
        for option in options:
            if option.get("value") != "Done":
                action_list.append(option.get("key"))

        artifact_filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "action",
                    "operator": "in",
                    "value": action_list
                }
            ]
        }
        result = Knowledge.list(artifact_filter)
        return result


class Message(object):
    WORKSHEET_ID = "message"

    def __init__(self):
        pass

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Message.WORKSHEET_ID, filter, include_system_fields=False)
        return result

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Message.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Message.WORKSHEET_ID, row_id, fields)
        return row_id


class Notice(object):
    @staticmethod
    def send(user, title, body=None):
        result = requests.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user})
        return result
